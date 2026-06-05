#Use packaging library to handle version specifiers
from packaging.version import Version, parse

v0 = Version("1.0")
v1 = Version("0.0.1.dev1")
v2 = Version("0.0.1.dev2")
v3 = Version("0.0.1.dev3")
v4 = Version("1.1.5")

major = v0.major
print(major)
minor = v0.minor
print(minor)
micro = v0.micro
print(micro)
epoch = v0.epoch
pre = v0.pre
print(pre)
post = v0.post
print(post)
dev = v0.dev
print(dev)

##order by major
from packaging.specifiers import SpecifierSet
from packaging.requirements import Requirement


r = Requirement('typer>=0.16.0; extra == "cli"')
print(r.marker)