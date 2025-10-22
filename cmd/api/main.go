package main

import (
	"fmt"

	"github.com/joho/godotenv"
	"github.com/juancwu/guangli/internal/config"
)

func main() {
	// load up env
	godotenv.Load(".env")

	cfg, err := config.GetConfig()
	if err != nil {
		panic(err)
	}

	fmt.Printf("configuration: %v\n", cfg)
}
