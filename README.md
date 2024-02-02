# SoftwareSeguro

Este script de Python, inspirado en la creación de C4l1b4n, forma parte de su repositorio NoSQL-Attack-Suite. La herramienta está diseñada para probar la vulnerabilidad de autenticación en solicitudes GET, POST y POST JSON, específicamente buscando posibles bypass en sistemas NoSQL.

Uso
Asegúrate de tener Python instalado en tu sistema antes de ejecutar el script.

Requisitos
Python 3.x
Bibliotecas de Python: requests, argparse

## Ejecución
python script.py -t <URL> -u <parametro_usuario> -p <parametro_contraseña> -o "<otros_parametros>"

Argumentos
-t: URL de destino.
-u: Parámetro de nombre de usuario.
-p: Parámetro de contraseña.
-o: Otros parámetros, separados por coma.

Ejemplo
python script.py -t https://0ad800e903755cef80b3bcb500330092.web-security-academy.net/login -u user -p password -o "login=login"

## Créditos
Este script está inspirado en la creación de C4l1b4n y forma parte de su repositorio NoSQL-Attack-Suite. Todos los derechos y créditos son atribuidos a él por la creación y contribución de esta herramienta. Puedes encontrar el código original en su repositorio de GitHub.
