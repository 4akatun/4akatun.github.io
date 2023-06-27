---
layout: post
tag: tags
---

## * **Script php**

```php
<?php
  $phar = new Phar('test.phar');
  $phar->addFile('prueba.php');
?>
-> command to execute script: php --define phar.readonly=0 <script_name>
 ```
