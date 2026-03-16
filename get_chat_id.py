#!/usr/bin/env python3
"""
KittyPaw Scanner — Telegram Chat ID Helper

Run this script AFTER messaging your bot on Telegram.
It fetches the latest update and prints your chat_id.

Usage:
  python get_chat_id.py --token YOUR_BOT_TOKEN

Steps:
  1. Open Telegram → search for your bot (@Kittypawscannerbot)
  2. Send any message to the bot (e.g. "hello")
  3. Run:  python get_chat_id.py --token 123456789:ABCxxx...
  4. Copy the chat_id and add it to your .env file
"""

import sys
import argparse
import requests


def get_chat_id(token: str) -> None:
    url = f"https://api.telegram.org/bot{token}/getUpdates"
    print(f"\nFetching updates from Telegram API …\n")
    try:
        r = requests.get(url, timeout=10)
        data = r.json()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    if not data.get("ok"):
        desc = data.get("description", "unknown error")
        print(f"❌  API error: {desc}")
        print("\nCheck that your bot token is correct.")
        sys.exit(1)

    results = data.get("result", [])
    if not results:
        print("❌  No messages found.")
        print("\n→  Send a message to your bot first, then run this script again.")
        sys.exit(1)

    seen = set()
    for update in results:
        msg = update.get("message") or update.get("channel_post") or {}
        chat = msg.get("chat", {})
        chat_id = chat.get("id")
        chat_type = chat.get("type", "?")
        chat_name = chat.get("title") or chat.get("username") or chat.get("first_name") or "?"

        if chat_id and chat_id not in seen:
            seen.add(chat_id)
            print(f"  Chat ID   : {chat_id}")
            print(f"  Chat type : {chat_type}")
            print(f"  Chat name : {chat_name}")
            print()

    if seen:
        print("─" * 40)
        print("Add to your .env file:")
        print(f"TELEGRAM_CHAT_ID={list(seen)[0]}")
        print("─" * 40)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find your Telegram chat ID")
    parser.add_argument("--token", required=True, help="Your Telegram bot token")
    args = parser.parse_args()
    get_chat_id(args.token)
