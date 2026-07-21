# Create the main directory and sub-folders for different evidence types
mkdir -p mock_evidence/{chat_logs,financial_records,social_media_scrapes}

# Populate Mock File 1: A chat log export
cat << 'EOF' > mock_evidence/chat_logs/export_001.txt
DATE: 2026-07-15 14:32:00
PLATFORM: EncryptedMessenger
PARTICIPANTS: DarkNet_Phantom, User_4882
---
DarkNet_Phantom: Did you secure the drop location at 1010 Main St?
User_4882: Yes. Used the vehicle with WA-Plate-XYZ123.
DarkNet_Phantom: Good. Call me on the burner if there are issues: 555-019-2039.
EOF

# Populate Mock File 2: A financial ledger
cat << 'EOF' > mock_evidence/financial_records/crypto_ledger.txt
DATE: 2026-07-18
TRANSACTION_ID: TXN-99382-A
AMOUNT: $4,500.00 USD
RECIPIENT_ALIAS: DarkNet_Phantom
NOTES: Payment for secured transport.
EOF

# Populate Mock File 3: A social media scrape
cat << 'EOF' > mock_evidence/social_media_scrapes/profile_scrape.txt
TARGET: John Doe
KNOWN_ALIASES: J_Doe_88, Phantom
LOCATION_PING: Vicinity of 1010 Main St.
ASSOCIATED_VEHICLES: Gray Sedan (WA-Plate-XYZ123)
EOF

chmod -R 444 mock_evidence/*