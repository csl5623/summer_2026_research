from itertools import batched

from packaging.specifiers import SpecifierSet,Specifier
from packaging.version import Version
from packaging.requirements import Requirement

# NOTICE: This file is a derivative work adapted from the PyPA 
# 'packaging' library (specifically the specifier range calculations).
# Modified by Carla Lopez

def get_ranges(specifierSet):
    spec = SpecifierSet(specifierSet)
    if not spec:
        return None
    result = None
    for i in spec:
        if result is None:
           result = spec_range(i)
        else:
            result = merge_ranges(result,spec_range(i))
            if not result:
                break
    return result
        
def spec_range(i: Specifier):
    op = i.operator
    v = i.version
    result = list()
    if op == "===":
        return [(make_bound(None, True), make_bound(None, True))]
    if v.endswith(".*"):
        result = wildcard_ranges(op, v)
    else:
        result = standard_ranges(op, v)
    return result

def range_is_empty(lower, upper):
    if lower["version"] is None or upper["version"] is None:
        return False
    if lower["version"] == upper["version"]:
        return not (lower["inclusive"] and upper["inclusive"])
    return lower["version"] > upper["version"]

def bounds_max(bound1,bound2):    
    if bound1["version"] is None:
        return bound2
    if bound2["version"] is None:
        return bound1
    
    if bound1["version"] != bound2["version"]:
        value = max(bound1["version"],bound2["version"])
        if bound2["version"] == value:
            return bound2
        else:
            return bound1
    ##handle the inclusive or exclusive stuff
    if  bound1["inclusive"] and bound2["inclusive"]:
        return bound1
    elif bound2["inclusive"] == False and bound1["inclusive"]:
        return bound2
    elif bound1["inclusive"] == False and bound2["inclusive"]:
        return bound1
    else:
        return bound1

def bounds_min(bound1,bound2):    
    if bound1["version"] is None:
        return bound2
    if bound2["version"] is None:
        return bound1
    if bound1["version"] != bound2["version"]:
        value = min(bound1["version"],bound2["version"])
        if bound2["version"] == value:
            return bound2
        else:
            return bound1
        ##how to know which min value belongs to which bound
    
    if  bound1["inclusive"] and bound2["inclusive"]:
        return bound1
    elif bound2["inclusive"] == False and bound1["inclusive"]:
        return bound2
    elif bound1["inclusive"] == False and bound2["inclusive"]:
        return bound1
    else:
        return bound1
    

def is_right_greater_than_left(left,right):
    if left["version"] is None:
        return False
    if right["version"] is None:
        return True
    if right["version"] != left["version"]:
        return left["version"] < right["version"]
    ##if they are the same, we compare inclusive or not inclusive
    if right["inclusive"] == left["inclusive"]:
        return False
    elif left["inclusive"] == False and right["inclusive"]:
        return True
    else:
        return True

def merge_ranges(left_range,right_range):
    ranges = list()
    left_index = 0
    right_index = 0
    
    while left_index < len(left_range) and right_index < len(right_range):
        left_lower, left_max = left_range[left_index]
        right_lower, right_max = right_range[right_index] 
        
        lower = bounds_max(left_lower, right_lower)
        upper = bounds_min(left_max, right_max)

        if not range_is_empty(lower, upper):
            ranges.append((lower, upper))

        if is_right_greater_than_left(left_max,right_max):
            left_index +=1
        else:
            right_index +=1     
    return ranges

def make_bound(version, inclusive):
        return {"version": version, "inclusive": inclusive}

def wildcard_ranges(op,v:str):
    p2 = v[:-2]
    try:
        version = Version(p2)
    except Exception as e:
        return []
    release = version.release
    
    increase = release[-1] + 1
    new_release = release[:-1] + (increase,)
    upper_bound = Version.from_parts(epoch=version.epoch,release=(new_release),dev=0)
    lower_bound = Version.from_parts(epoch=version.epoch,release=release,dev=0)
    
    if op == "==":
        return [
            (make_bound(lower_bound,True),make_bound(upper_bound,True))
        ]
    return [
        (make_bound(None,True),make_bound(lower_bound,False)),
        (make_bound(upper_bound,True),make_bound(None,False))
    ]

def standard_ranges(op,v):
    min_version  =Version("0.dev0")
    try:
        version = Version(v)
    except Exception as e:
        return 
    
    if op == ">=":
        return [(make_bound(version,True),make_bound(None,True))]
    
    if op == "<=":
        return [(make_bound(min_version,True),make_bound(version,True))]
    
    if op == "<":
        bound = version if version.is_prerelease else version.__replace__(dev=0, local=None)
        if bound <= min_version:
            return []
        return [(make_bound(min_version,False),make_bound(version, False))]
    if op == ">":
        return [(make_bound(version,False),make_bound(None,True))]
    
    if op == "==":
        return [(make_bound(version, True),make_bound(version, True))]
    
    if op == "!=":
        return [
            (make_bound(min_version,True),make_bound(version,False)),
            (make_bound(version,False),make_bound(None,True))
        ]
        
    if op == "~=":
        prefix_tuple = list(version.release[:-1])
        prefix_tuple[-1] = prefix_tuple[-1] + 1
        upper_bound = Version.from_parts(epoch=version.epoch,release=(tuple(prefix_tuple)),dev=0)
        return [
                (make_bound(version, True),make_bound(upper_bound, False))
        ]

