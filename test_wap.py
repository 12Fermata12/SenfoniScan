from Wappalyzer import Wappalyzer, WebPage
wappalyzer = Wappalyzer.latest()
webpage = WebPage.new_from_url('https://tekden.com.tr')
print(wappalyzer.analyze(webpage))
