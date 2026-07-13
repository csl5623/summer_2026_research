from packaging.specifiers import SpecifierSet
from packaging.version import Version

def extract_string_version(bound):
    if hasattr(bound,"version"):
        return str(bound.version)
    else:
        return str(bound)
        
def handle_ranges_private_methods(specifier : SpecifierSet):
    ranges_list = []
    ranges = specifier._get_ranges()
    for lower_bound, upper_bound in ranges:
        lower_bound_version = lower_bound.version
        lower_bound_inclusive = lower_bound.inclusive
        upper_bound_version = upper_bound.version
        upper_bound_inclusive = upper_bound.inclusive
        
        if lower_bound_version:
            lower = extract_string_version(lower_bound_version)
            print(lower)
            print(lower_bound_inclusive)
        if upper_bound_version:   
            print("upper bound: " + extract_string_version(upper_bound_version))
            ranges_list.append((lower,lower_bound_inclusive))
         
handle_ranges_private_methods(SpecifierSet(">=1.0.0"))