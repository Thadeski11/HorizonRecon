import dnsclass
import saidas
import argparse

dns = dnsclass.Dnsscan
saida = saidas.Saidas

parser = argparse.ArgumentParser(prog="Horizonrecon", description="Scans de Domínio")
parser.add_argument("--type", help='''
Escolha a ferramenta que vai utilizar: 
[sub] - Verificar subdominios ativos
[cname] - Checar se os subdominios possuem um alias
[whois] - Consultar informações de Whois 
''')
parser.add_argument("--domain", help="Passar o domínio alvo.")
parser.add_argument("--wordlist", help="Passar a payload de testes.")
parser.add_argument("--ipv", help="Digite [4] para ipv4, [6] para ipv6, [all] para ambos")
parser.add_argument("--output", help="Salva resultados em um arquivo de texto simples")
parser.add_argument("--json", help="Salvar resultados em um arquivo JSON")
args = parser.parse_args()

if args.type == "cname":
	async def run_check_cname():
		check_cname = dns.CheckCNAME()
		results_cname = await check_cname.Main(args.domain, args.wordlist)
		for i in results_cname:
			print(i)
		return results_cname
	results_cname = asyncio.run(run_check_cname())
	saida.output_comum(results_cname, args.output)
	saida.output_json(results_cname, args.json)
elif args.type == "sub":
	verifica_subdominio_ativo = dns.SubdomainBF(args.domain, args.wordlist, args.ipv)
	saida.output_comum(verifica_subdominio_ativo, args.output)
	saida.output_json(verifica_subdominio_ativo, args.json)
elif args.type == "whois":
	consulta_whois = dns.Whois(args.domain)
	saida.output_comum(consulta_whois, args.output)
	saida.output_json(consulta_whois, args.json)
