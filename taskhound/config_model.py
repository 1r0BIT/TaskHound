"""Configuration model for TaskHound BloodHound integration."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class BloodHoundConfig:
    """
    Consolidated BloodHound configuration from CLI args and config file.
    
    Merges settings from:
    1. Command-line arguments (highest priority)
    2. bh_connector.config file (if present)
    3. Defaults
    """
    # OpenGraph generation
    bh_opengraph: bool = False
    bh_output: str = "./opengraph"
    bh_no_upload: bool = False
    
    # BloodHound connection
    bh_connector: Optional[str] = None
    bh_username: Optional[str] = None
    bh_password: Optional[str] = None
    bh_type: Optional[str] = None  # 'bhce' or 'legacy'
    
    # Icon configuration
    bh_set_icon: bool = False
    bh_force_icon: bool = False
    bh_icon: str = "heart"
    bh_color: str = "#8B5CF6"
    
    # Live connection (legacy)
    bh_live: bool = False
    bh_save: Optional[str] = None
    
    @classmethod
    def from_args_and_config(cls, args, config_data: Optional[dict] = None):
        """
        Create BloodHoundConfig by merging CLI args and config file.
        
        Priority:
        1. CLI arguments (if explicitly provided)
        2. Config file values
        3. Defaults
        
        Args:
            args: argparse.Namespace from CLI
            config_data: Dict loaded from bh_connector.config (or None)
            
        Returns:
            BloodHoundConfig instance
        """
        # Start with args (they may have defaults)
        config = cls(
            # OpenGraph
            bh_opengraph=args.bh_opengraph,
            bh_output=args.bh_output,
            bh_no_upload=args.bh_no_upload,
            
            # Connection
            bh_connector=args.bh_connector,
            
            # Icon
            bh_set_icon=args.bh_set_icon,
            bh_force_icon=args.bh_force_icon,
            bh_icon=args.bh_icon,
            bh_color=args.bh_color,
            
            # Live (legacy)
            bh_live=args.bh_live,
            bh_save=args.bh_save,
        )
        
        # Override with config file if present
        if config_data:
            # Auto-enable OpenGraph if BHCE type is set in config
            if not config.bh_opengraph and config_data.get('type') == 'bhce':
                config.bh_opengraph = True
            
            # Set connector if not provided via CLI
            if not config.bh_connector or config.bh_connector == "http://127.0.0.1:8080":
                if 'url' in config_data:
                    config.bh_connector = config_data['url']
            
            # Set credentials if not provided via CLI
            if not config.bh_username and 'username' in config_data:
                config.bh_username = config_data['username']
            
            if not config.bh_password and 'password' in config_data:
                config.bh_password = config_data['password']
            
            # Set type if not determined
            if not config.bh_type and 'type' in config_data:
                config.bh_type = config_data['type']
        
        # Determine type from CLI flags if not set
        if not config.bh_type:
            if args.bhce:
                config.bh_type = 'bhce'
            elif args.legacy:
                config.bh_type = 'legacy'
        
        return config
    
    def has_credentials(self) -> bool:
        """Check if BloodHound credentials are available."""
        return bool(self.bh_username and self.bh_password)
    
    def is_bhce(self) -> bool:
        """Check if this is BloodHound Community Edition."""
        return self.bh_type == 'bhce'
    
    def is_legacy(self) -> bool:
        """Check if this is Legacy BloodHound (Neo4j)."""
        return self.bh_type == 'legacy'
