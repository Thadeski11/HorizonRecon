import json 

class Saidas():
	def output_comum(tool, nome_arquivo):
		arquivo_texto_simples = tool
		if nome_arquivo:
			with open(f"{nome_arquivo}", "w") as f:
				f.write(arquivo_texto_simples)
		else:
			None

	def output_json(tool, nome_arquivo):
		arquivo_json = json.dumps(tool)
		if nome_arquivo:
			with open(f"{nome_arquivo}", "w") as f:
				f.write(arquivo_json)
		else:
			None
