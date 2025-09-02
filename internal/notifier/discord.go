/*
Handles sending CVE alerts to Discord channels using discordgo.
It supports multiple categories and avoids message flood by spacing the messages.

Last Updated: 2025-09-01
*/

package notifier

import (
	"fmt"
	"log"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/livingdotone/vulnhound/internal/filter"
	"github.com/spf13/viper"
)

const batchSize = 5                // quantos CVEs por rodada
const batchDelay = 3 * time.Second // delay entre rodadas

type DiscordNotifier struct {
	Session        *discordgo.Session
	channelByCat   map[string]string
	defaultChannel string
}

func New(token string, channels map[string]string, delay time.Duration) (*DiscordNotifier, error) {
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		return nil, fmt.Errorf("error creating Discord session: %w", err)
	}

	err = dg.Open()
	if err != nil {
		return nil, fmt.Errorf("error opening Discord session: %w", err)
	}

	channelByCat := map[string]string{
		"Web/SQLi 🌐":            viper.GetString("DISCORD_CHANNEL_WEB"),
		"Web/XSS 🌐":             viper.GetString("DISCORD_CHANNEL_WEB"),
		"Web/CSRF 🌐":            viper.GetString("DISCORD_CHANNEL_WEB"),
		"Web/Deserialization 🌐": viper.GetString("DISCORD_CHANNEL_WEB"),
		"Linux 🐧":               viper.GetString("DISCORD_CHANNEL_LINUX"),
		"Windows 🪟":             viper.GetString("DISCORD_CHANNEL_WINDOWS"),
		"Mac 🍏":                 viper.GetString("DISCORD_CHANNEL_MAC"),
		"Mobile/Android 📱":      viper.GetString("DISCORD_CHANNEL_ANDROID"),
		"Mobile/iOS 📱":          viper.GetString("DISCORD_CHANNEL_IOS"),
	}

	return &DiscordNotifier{
		Session:        dg,
		channelByCat:   channelByCat,
		defaultChannel: viper.GetString("DISCORD_CHANNEL_DEFAULT"),
	}, nil
}

func (n *DiscordNotifier) Close() {
	n.Session.Close()
}

func (n *DiscordNotifier) SendCVE(cve filter.CveInfo) error {
	// pick channel by category
	channelID, ok := n.channelByCat[cve.Category]
	if !ok || channelID == "" {
		channelID = n.defaultChannel
	}
	if channelID == "" {
		return fmt.Errorf("no channel configured for category %s", cve.Category)
	}

	embed := &discordgo.MessageEmbed{
		Title:       fmt.Sprintf("%s", cve.ID),
		URL:         fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.ID),
		Description: cve.Description,
		Color:       cve.Color,
		Fields: []*discordgo.MessageEmbedField{
			{
				Name:   "Severity",
				Value:  fmt.Sprintf("%s (%.1f)", cve.Severity, cve.Score),
				Inline: true,
			},
			{
				Name:   "Category",
				Value:  cve.Category,
				Inline: true,
			},
		},
		Footer: &discordgo.MessageEmbedFooter{
			Text: "Powered by VulnHound 🐺",
		},
	}

	_, err := n.Session.ChannelMessageSendEmbed(channelID, embed)
	if err != nil {
		log.Printf("❌ Failed to send CVE %s: %v", cve.ID, err)
		return err
	}

	log.Printf("✅ Sent %s to channel %s", cve.ID, channelID)
	return nil
}

func (n *DiscordNotifier) SendCVEs(cves []filter.CveInfo) {
	for i := 0; i < len(cves); i += batchSize {
		end := i + batchSize
		if end > len(cves) {
			end = len(cves)
		}

		batch := cves[i:end]
		for _, cve := range batch {
			_ = n.SendCVE(cve)
		}

		if end < len(cves) {
			log.Printf("⏳ Waiting %s before sending next batch...", batchDelay)
			time.Sleep(batchDelay)
		}
	}
}

// Start opens the Discord session (required for bots)
func (n *DiscordNotifier) Start() error {
	return n.Session.Open()
}

// Stop closes the Discord session
func (n *DiscordNotifier) Stop() {
	_ = n.Session.Close()
}
