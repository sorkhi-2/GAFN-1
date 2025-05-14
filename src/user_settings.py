# Please modify the settings below according to your needs.

# List of source URLs to fetch proxy configurations from.
# Add or remove URLs as needed. All URLs in this list are automatically enabled.
SOURCE_URLS = [
    "https://getafreenode.com/subscribe/?uuid=942b9cb8-92fa-46ac-ae91-f69c8234434b",
    "https://getafreenode.com/subscribe/?uuid=0cb527d9-6117-4bcf-a52b-1704b3458cef",
    "https://getafreenode.com/subscribe/?uuid=9c859345-959f-491b-b6fc-65cd7a57aeb3",
    "https://getafreenode.com/subscribe/?uuid=f901861b-6491-450c-b500-606b2e921625",
    "https://getafreenode.com/subscribe/?uuid=5eaa121d-4362-444d-8219-29b02c35303a",
    "https://getafreenode.com/subscribe/?uuid=413c8b50-96bf-4457-82f2-54dfa8685f53",
    "https://getafreenode.com/subscribe/?uuid=ebbeef45-0fd8-40cd-aca5-1e2ce18abeff",
    "https://getafreenode.com/subscribe/?uuid=e31ad3e6-e341-42ac-bdc7-bea02d126fc1",
    "https://getafreenode.com/subscribe/?uuid=4685eb2a-5ddb-4dc6-9e53-f0c90d6124c1",
    "https://getafreenode.com/subscribe/?uuid=55ca7a9e-cf90-49df-b14a-9346c59b73b9",
    # Add more URLs here if you want to include additional sources.
]

# Set to True to fetch the maximum possible number of configurations.
# If True, SPECIFIC_CONFIG_COUNT will be ignored.
USE_MAXIMUM_POWER = True

# Desired number of configurations to fetch.
# This is used only if USE_MAXIMUM_POWER is False.
SPECIFIC_CONFIG_COUNT = 1000

# Dictionary of protocols to enable or disable.
# Set each protocol to True to enable, False to disable.
ENABLED_PROTOCOLS = {
    "wireguard://": False,
    "hysteria2://": True,
    "vless://": False,
    "vmess://": False,
    "ss://": False,
    "trojan://": False,
    "tuic://": False,
}

# Maximum age of configurations in days.
# Configurations older than this will be considered invalid.
MAX_CONFIG_AGE_DAYS = 365
