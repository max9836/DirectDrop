# PIM (Personal Iteration Multiplier) for password hashing
# Recommended: >= 600 for security, 6144 is a good balance of security and performance
pim = 6144

# Timeout (in seconds) when attempting to connect to a remote peer
connect_timeout: int = 10

# Toggle low memory mode (encrypts each chunk separately to reduce RAM usage)
low_mem_mode: bool = False

# Delay between sending each packet (in milliseconds)
# Helps prevent buffer overflows and data corruption, especially on unstable networks
throttling_delay: int = 10

# DO NOT set above 2GB; socket buffer limits can cause packet corruption
strict_packet_chunk_size: int = 4190912               # For strict mode
non_strict_packet_chunk_size: int = 2147479552        # For non-strict mode

# Packet size for low memory mode; 4MB default. Change depending on RAM and file size.
# Safe: 10KB (low RAM), 1MB/1GB (high-performance systems)
low_mem_mode_packet_chunk_size: int = 4190912

# Number of passes used to overwrite sensitive memory
MEMORY_SHRED_PASSES:int = 5
