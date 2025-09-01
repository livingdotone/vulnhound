package main

import (
	"fmt"
	"log"
	"time"

	"github.com/livingdotone/vulnhound/internal/fetcher"
	"github.com/livingdotone/vulnhound/internal/notifier"
	"github.com/spf13/viper"
)

type Config struct {
	DiscordToken string
	Channels     map[string]string
	DelaySeconds int
}

func LoadConfig() *Config {
	viper.SetConfigFile(".env")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Println("Warning: could not read .env file, relying on environment variables")
	}

	return &Config{
		DiscordToken: viper.GetString("DISCORD_BOT_TOKEN"),
		Channels: map[string]string{
			"web":     viper.GetString("CHANNEL_VULNS_WEB"),
			"linux":   viper.GetString("CHANNEL_VULNS_LINUX"),
			"windows": viper.GetString("CHANNEL_VULNS_WINDOWS"),
		},
	}
}

func main() {
	cfg := LoadConfig()

	if cfg.DiscordToken == "" {
		log.Fatal("DISCORD_BOT_TOKEN not set")
	}

	delay := time.Duration(2) * time.Second

	n, err := notifier.New(cfg.DiscordToken, cfg.Channels, delay)
	if err != nil {
		log.Fatal(err)
	}
	defer n.Close()

	cves, err := fetcher.FetchNVDCVEs(fetcher.CVEQuery{
		PubStart:   "2025-08-25T00:00:00Z",
		PubEnd:     "2025-09-01T00:00:00Z",
		MaxResults: 50,
	})
	if err != nil {
		log.Fatal(err)
	}

	n.SendCVEs(cves)

	fmt.Println("Finished sending CVEs to Discord channels.")
}
