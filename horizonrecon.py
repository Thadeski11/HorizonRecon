import dnsclass
import saidas
import argparse
import asyncio

dns = dnsclass.Dnsscan
saida = saidas.Saidas

parser = argparse.ArgumentParser(prog="Horizonrecon", description="Scans de Domínio")
parser.add_argument("--type", help='''
Escolha a ferramenta que vai utilizar: 
[sub] - Verificar subdominios ativos
[cname] - Checar se os subdominios possuem um alias
[whois] - Consultar informações de Whois 
''')
parser.add_argument("-d", "--domain", help="Passar o domínio alvo.")
parser.add_argument("-w", "--wordlist", help="Passar a payload de testes.")
parser.add_argument("-t", "--time", type=int, default=5, help="Definir tempo limite por segundo")
parser.add_argument("--ipv", help="Digite [4] para ipv4, [6] para ipv6, [all] para ambos")
parser.add_argument("-o", "--output", help="Salva resultados em um arquivo de texto simples")
parser.add_argument("-j", "--json", help="Salvar resultados em um arquivo JSON")
args = parser.parse_args()

if args.type == "cname":
	async def run_check_cname():
		check_cname = dns.CheckCNAME()
		results_cname = await check_cname.Main(args.domain, args.wordlist, args.time)
		for i in results_cname:
			print(i)
		return results_cname
	results_cname = asyncio.run(run_check_cname())
	saida.output_comum(results_cname, args.output)
	saida.output_json(results_cname, args.json)
elif args.type == "sub":
	async def run_check_subdomain():
		subdomainbf = dns.SubdomainBF()
		results_subdomains = await subdomainbf.Main(args.domain, args.wordlist, args.time, args.ipv)
		print(results_subdomains)
		return results_subdomains
	results_subdomains = asyncio.run(run_check_subdomain())
	saida.output_comum(results_subdomains, args.output)
	saida.output_json(results_subdomains, args.json)
elif args.type == "whois":
	consulta_whois = dns.Whois(args.domain)
	saida.output_comum(consulta_whois, args.output)
	saida.output_json(consulta_whois, args.json)
