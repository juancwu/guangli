package config

import (
	"fmt"
	"os"
	"regexp"
	"sync"

	"github.com/juancwu/guangli/internal/errors"
	"github.com/spf13/viper"
)

type (
	Config struct {
		Environment string     `mapstructure:"environment"`
		App         App        `mapstructure:"app"`
		Network     Network    `mapstructure:"network"`
		Database    Database   `mapstructure:"database"`
		Auth        Auth       `mapstructure:"auth"`
		SMTPServer  SMTPServer `mapstructure:"smtp_server"`
	}

	App struct {
		// The application name. This is used in alert emails
		Name string `mapstructure:"name"`
		// The timezone the server should use for all timestamps.
		Timezone string `mapstructure:"timezone"`
	}

	Network struct {
		// Host represents the host the server should bind to. This
		// is not necessarily the same as Domain. Domain is more like
		// the publicly facing domain name that is used to reach the server.
		Host string `mapstructure:"host"`
		// Port represents the port that the server should bind to.
		Port int `mapstructure:"port"`
		// Domain represents the entire url that the public can access to.
		// This is can be different than Host and Port since the server
		// can be binded to localhost on some port behind a reverse proxy.
		Domain string `mapstructure:"domain"`
	}

	Database struct {
		// For PostgreSQL, MySQL databases provide a complete string with credentials
		DSN string `mapstructure:"dsn"`
		// The driver is a string value that can be one of: pgsql, mysql or sqlite
		Driver string `mapstructure:"driver"`
	}

	Auth struct {
		AccessToken   JWT           `mapstructure:"access_token"`
		RefreshCookie SessionCookie `mapstructure:"refresh_cookie"`
	}

	JWT struct {
		// The secret to use to sign the JWT
		Secret    string `mapstructure:"secret"`
		Issuer    string `mapstructure:"iss"`
		Audience  string `mapstructure:"aud"`
		ExpiresIn string `mapstructure:"expires_in"`
	}

	SessionCookie struct {
		// The secret use to sign the session cookie.
		// This is important to properly validate the session cookie
		// and allow the server to validate existing sessions if a reboot happens.
		Secret string `mapstructure:"secret"`
		Name   string `mapstructure:"name"`
		Domain string `mapstructure:"domain"`
		Secure bool   `mapstructure:"secure"`
		// By default the path would be the most up to date refresh api endpoint.
		// If another path is desired (i.e: when running the client in a reverse proxy),
		// set the path that it is expected for the browser to include the session cookie
		// to properly forward it to the right path.
		Path     string `mapstructure:"path"`
		HttpOnly bool   `mapstructure:"http_only"`
		SameSite string `mapstructure:"same_site"`
		MaxAge   string `mapstructure:"max_age"`
	}

	// SMTPServer is used for admin alert emails only.
	SMTPServer struct {
		Port     int    `mapstructure:"port"`
		Host     string `mapstructure:"host"`
		Username string `mapstructure:"username"`
		Password string `mapstructure:"password"`
		Email    string `mapstructure:"email"`
	}
)

var globalCfg *Config = nil
var localV *viper.Viper = nil
var once sync.Once
var lock sync.Mutex

// GetConfig returns a reference of the currently loaded configuration.
// If not loaded, it will lazy load the configuration.
func GetConfig() (*Config, error) {
	if globalCfg == nil || localV == nil {
		if err := load(); err != nil {
			return nil, errors.E(errors.Op("config.GetConfig"), errors.KindUnexpected, err)
		}
	}

	return globalCfg, nil
}

// ReloadConfig reloads the configuration on demand.
func ReloadConfig() error {
	op := errors.Op("config.ReloadConfig")
	if globalCfg == nil || localV == nil {
		if err := load(); err != nil {
			return errors.E(op, errors.KindUnexpected, err)
		}
	}

	lock.Lock()
	defer lock.Unlock()

	if err := localV.ReadInConfig(); err != nil {
		return errors.E(op, errors.KindUnexpected, err)
	}

	return nil
}

// Load loads the configuration json file. The loaded configuration is immutable.
func load() (err error) {
	lock.Lock()
	defer lock.Unlock()

	op := errors.Op("config.load")

	once.Do(func() {
		localV = viper.New()

		localV.SetConfigName("config")
		localV.SetConfigType("yaml")
		localV.AddConfigPath(".")

		if err = localV.ReadInConfig(); err != nil {
			return
		}

		if err = substituteEnvVars(localV); err != nil {
			return
		}

		// Unmarshal needs an addressible pointer so we must declare a variable first
		var cfg Config
		if err = localV.Unmarshal(&cfg); err != nil {
			return
		}
		globalCfg = &cfg

	})

	if err != nil {
		return errors.E(op, errors.KindUnexpected, err)
	}

	return nil
}

func substituteEnvVars(v *viper.Viper) error {
	op := errors.Op("config.substituteEnvVars")

	// regex to match ${VARIABLE_NAME}
	envVarRegex := regexp.MustCompile(`\$\{([^}]+)\}`)

	// substitution
	for _, key := range v.AllKeys() {
		originalValue := v.Get(key)

		switch value := originalValue.(type) {
		case string:
			if substituted, newValue := getEnvVar(envVarRegex, value); substituted {
				v.Set(key, newValue)
			}

		case []string:
			newSlice := make([]string, len(value))
			substitutedInSlice := false
			for i, str := range value {
				if substituted, newStr := getEnvVar(envVarRegex, str); substituted {
					newSlice[i] = newStr
					substitutedInSlice = true
				} else {
					newSlice[i] = str
				}
			}
			if substitutedInSlice {
				v.Set(key, newSlice)
			}

		case []any:
			newSlice := make([]any, len(value))
			substitutedInSlice := false
			for i, item := range value {
				// Check if item in slice is a string
				if itemStr, ok := item.(string); ok {
					if substituted, newItemStr := getEnvVar(envVarRegex, itemStr); substituted {
						newSlice[i] = newItemStr
						substitutedInSlice = true
					} else {
						newSlice[i] = itemStr // No substitution, keep original
					}
				} else {
					newSlice[i] = item // Not a string, keep original
				}
			}

			if substitutedInSlice {
				v.Set(key, newSlice)
			}

		}
	}

	// This loop now checks all values, including strings inside slices.
	for _, key := range v.AllKeys() {
		value := v.Get(key)

		switch v := value.(type) {
		case string:
			if err := checkUnresolved(envVarRegex, v, key); err != nil {
				return errors.E(op, errors.KindUnexpected, err)
			}
		case []any:
			for _, item := range v {
				if itemStr, ok := item.(string); ok {
					if err := checkUnresolved(envVarRegex, itemStr, key); err != nil {
						return errors.E(op, errors.KindUnexpected, err)
					}
				}
			}
		case []string:
			for _, itemStr := range v {
				if err := checkUnresolved(envVarRegex, itemStr, key); err != nil {
					return errors.E(op, errors.KindUnexpected, err)
				}
			}
		}
	}

	return nil
}

func getEnvVar(envVarRegex *regexp.Regexp, value string) (bool, string) {
	if !envVarRegex.MatchString(value) {
		return false, value
	}

	newValue := envVarRegex.ReplaceAllStringFunc(value, func(match string) string {
		varName := match[2 : len(match)-1]

		// Use os.LookupEnv to distinguish between empty and unset
		if envValue, ok := os.LookupEnv(varName); ok {
			return envValue
		}

		// return the original match if no environment variable found
		return match
	})

	// Return true only if a substitution actually occurred
	return newValue != value, newValue
}

// checkUnresolved scans a string for any unresolved env var patterns and returns an error if found.
func checkUnresolved(r *regexp.Regexp, value string, key string) error {
	if r.MatchString(value) {
		matches := r.FindAllStringSubmatch(value, -1)
		for _, match := range matches {
			if len(match) > 1 {
				err := fmt.Errorf("environment variable %s not found for key %s", match[1], key)
				return errors.E(errors.Op("config.checkUnresolved"), errors.KindUnexpected, err)
			}
		}
	}
	return nil
}
