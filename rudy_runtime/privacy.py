def private_by_default(option):
    """Keep individual IP lookup results private unless the user explicitly opts out."""
    return option is not False
