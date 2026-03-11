import os, re

pf = open('ios/Podfile').read()
pf = '\n'.join(l for l in pf.splitlines() if ':privacy_file_aggregation_enabled' not in l)
if 'use_modular_headers!' not in pf:
    pf = pf.replace('use_react_native!', 'use_modular_headers!\n  use_react_native!', 1)

inject = """
    installer.pods_project.targets.each do |target|
      target.build_configurations.each do |config|
        config.build_settings['CLANG_CXX_LANGUAGE_STANDARD'] = 'c++17'
        config.build_settings['CLANG_CXX_LIBRARY'] = 'libc++'
      end
    end"""

if 'CLANG_CXX_LANGUAGE_STANDARD' not in pf:
    pf = re.sub(r'(post_install do \|installer\|)', r'\1' + inject, pf, count=1)

open('ios/Podfile', 'w').write(pf)

def patch(path, replacements):
    if not os.path.exists(path): return
    for root, dirs, files in os.walk(path):
        for f in files:
            if not f.endswith('.swift'): continue
            fp = os.path.join(root, f)
            txt = open(fp).read()
            for old, new in replacements: txt = txt.replace(old, new)
            open(fp, 'w').write(txt)

patch('node_modules/expo-apple-authentication/ios', [('switch error.code {', 'switch error.code {\n    @unknown default: break'),('switch credentialState {', 'switch credentialState {\n    @unknown default: break'),('switch status {', 'switch status {\n    @unknown default: break')])
patch('node_modules/expo-crypto/ios', [('class LossyConversionException: Exception', 'class LossyConversionException: Exception, @unchecked Sendable'),('class FailedGeneratingRandomBytesException: GenericException<OSStatus>', 'class FailedGeneratingRandomBytesException: GenericException<OSStatus>, @unchecked Sendable')])
print('done')
