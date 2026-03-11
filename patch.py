import re

pf = open('ios/Podfile').read()

# remove unsupported option
pf = re.sub(r':ccache_enabled\s*=>\s*true,?', '', pf)

# fix possible trailing commas after removal
pf = re.sub(r',\s*\)', ')', pf)

open('ios/Podfile','w').write(pf)

print('done')
