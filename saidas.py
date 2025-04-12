import json 

class Saidas():
	def output_comum(tool, nome_arquivo):
		if nome_arquivo:
			if isinstance(tool, list):
				with open(f"{nome_arquivo}", "w") as f:
					for i in tool:
						f.write(i)
						f.write("\n")
			elif isinstance(tool, dict):
				with open(f"{nome_arquivo}", "w") as f:
					for type, info in tool.items():
						f.write(f"{type}:\n")
						for host, ip in info.items():
							f.write(f"{host}: {ip}\n")
			else:
				with open(f"{nome_arquivo}", "w") as f:
					f.write(tool)
		else:
			None
			
	def output_json(tool, nome_arquivo):
		arquivo_json = json.dumps(tool)
		if nome_arquivo:
			with open(f"{nome_arquivo}", "w") as f:
				f.write(arquivo_json)
		else:
			None
