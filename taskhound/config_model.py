"""Configuration model for TaskHound BloodHound integration."""

from dataclasses import dataclass


@dataclass
class BloodHoundConfig:
    """
    Consolidated BloodHound configuration from CLI args and config file.

    Merges settings from:
    1. Command-line arguments (highest priority)
    2. taskhound.toml [bloodhound] section (if present)
    3. Defaults
    """

    # OpenGraph generation
    bh_opengraph: bool = False
    bh_no_upload: bool = False

    # BloodHound connection
    bh_connector: str | None = None
    bh_username: str | None = None
    bh_password: str | None = None
    bh_api_key: str | None = None  # API key for BHCE HMAC authentication
    bh_api_key_id: str | None = None  # API key ID for BHCE HMAC authentication
    bh_type: str | None = None  # 'bhce' or 'legacy'

    # Live connection (legacy)
    bh_live: bool = False
    bh_save: str | None = None

    @classmethod
    def from_args_and_config(cls, args):
        """
        Create BloodHoundConfig by merging CLI args and config file.

        Priority:
        1. CLI arguments (if explicitly provided)
        2. Config file values (loaded into args defaults)

        Args:
            args: argparse.Namespace from CLI

        Returns:
            BloodHoundConfig instance
        """
        # Start with args (they may have defaults)
        config = cls(
            # OpenGraph
            bh_opengraph=args.bh_opengraph,
            bh_no_upload=args.bh_no_upload,
            # Connection
            bh_connector=args.bh_connector,
            bh_username=args.bh_user,
            bh_password=args.bh_password,
            bh_api_key=args.bh_api_key,
            bh_api_key_id=args.bh_api_key_id,
            # Live (legacy)
            bh_live=args.bh_live,
            bh_save=args.bh_save,
        )

        # Determine type from CLI flags if not set
        if not config.bh_type:
            if args.bhce:
                config.bh_type = "bhce"
            elif args.legacy:
                config.bh_type = "legacy"
            else:
                # Default to BHCE if not specified
                config.bh_type = "bhce"

        return config

    def has_credentials(self) -> bool:
        """Check if BloodHound credentials are available."""
        # API key + key ID pair is sufficient for BHCE
        if self.bh_api_key and self.bh_api_key_id:
            return True
        # Otherwise need username and password
        return bool(self.bh_username and self.bh_password)

    def is_bhce(self) -> bool:
        """Check if this is BloodHound Community Edition."""
        return self.bh_type == "bhce"

    def is_legacy(self) -> bool:
        """Check if this is Legacy BloodHound (Neo4j)."""
        return self.bh_type == "legacy"
