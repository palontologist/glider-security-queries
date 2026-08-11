from glider import *


def query():
    """
    @title: Oracle price manipulation via single source
    @description: Detects contracts using single oracle price feed without manipulation checks.
                  Checks for missing TWAP, deviation thresholds, and heartbeat validation.
    @tags: oracle, price-manipulation, twap, chainlink
    @references: https://blog.chain.link/oracle-security/, https://samczsun.com/so-you-want-to-use-a-price-oracle/
    """

    return (
        Functions()
        .filter(uses_oracle_price)
        .exec()
        .filter(missing_oracle_validation)
    )


def uses_oracle_price(func):
    """Check if function reads from oracle"""
    oracle_patterns = [
        "latestRoundData", "getPrice", "getLatestPrice", "consult",
        "peek", "getRate", "price", "getAssetPrice"
    ]
    
    for inst in func.instructions().exec():
        callee_names = inst.callee_names()
        if any(pattern in c for c in callee_names for pattern in oracle_patterns):
            return True
        
        # Check for Chainlink AggregatorV3Interface calls
        for var in inst.vars_read():
            if "aggregator" in var.name.lower() or "oracle" in var.name.lower() or "pricefeed" in var.name.lower():
                if "latestRoundData" in str(inst):
                    return True
    
    return False


def missing_oracle_validation(func):
    """Check if oracle price usage lacks manipulation protection"""
    protections = {
        "twap": False,
        "deviation_check": False,
        "heartbeat": False,
        "multiple_sources": False,
        "min_max_bounds": False
    }
    
    for inst in func.instructions().exec():
        vars_read = [v.name.lower() for v in inst.vars_read()]
        callee_names = [c.lower() for c in inst.callee_names()]
        
        # TWAP check
        if any("twap" in v or "timeweighted" in v or "movingaverage" in v for v in vars_read):
            protections["twap"] = True
        
        # Deviation threshold
        if any("deviation" in v or "threshold" in v or "maxdiff" in v or "percent" in v for v in vars_read):
            if "require" in callee_names or "assert" in callee_names:
                protections["deviation_check"] = True
        
        # Heartbeat/staleness check
        if any("heartbeat" in v or "stale" in v or "updatedat" in v or "timestamp" in v for v in vars_read):
            if "require" in callee_names:
                protections["heartbeat"] = True
        
        # Multiple oracle sources
        oracle_count = sum(1 for v in vars_read if "oracle" in v or "aggregator" in v or "pricefeed" in v)
        if oracle_count > 1:
            protections["multiple_sources"] = True
        
        # Min/max bounds
        if any("minprice" in v or "maxprice" in v or "lowerbound" in v or "upperbound" in v for v in vars_read):
            protections["min_max_bounds"] = True
    
    # Require at least 2 protections
    return sum(protections.values()) < 2


def query_stale_price():
    """
    @title: Using stale oracle prices
    @description: Detects oracle price usage without timestamp/staleness validation
    @tags: oracle, stale-price, timestamp
    """
    return (
        Functions()
        .filter(uses_oracle_price)
        .exec()
        .filter(lambda f: not has_timestamp_check(f))
    )


def has_timestamp_check(func):
    """Check if function validates oracle timestamp"""
    for inst in func.instructions().exec():
        if "require" in inst.callee_names() or "assert" in inst.callee_names():
            for var in inst.vars_read():
                if "updatedat" in var.name.lower() or "timestamp" in var.name.lower() or "block.timestamp" in str(inst):
                    return True
    return False