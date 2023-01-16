import insidentil_id

username = "<username>"
password = "<password>"
shodan_api_key = "<api_key>"
elasticsearch_host = "<es_host>"

#

shodan_search = insidentil_id.shodan_search(shodan_api_key)
organizations=[
    # "org:'Kementerian Pertanian'", 
    # "org:'Kementerian Keuangan'", 
    # "org:'Badan Pengawas Obat dan Makanan' ", 
    # "org:'Badan Pengawasan Keuangan dan Pembangunan'", 
    # "org:'Departemen Energi dan Sumber Daya Mineral'", 
    # "org:'KEMENKO POLHUKAM RI'", 
    # "org:'Kementerian Pariwisata dan Ekonomi Kreatif'", 
    # "org:'Departemen Perindustrian Republik Indonesia'", 
    # "org:'Komisi Pemilihan Umum'", 
    # "org:'Departemen Pertahanan dan Keamanan Republik Indonesia'",
]
shodan_search.set_database()
shodan_search.set_elasticsearch_auth(elasticsearch_host, username, password)
shodan_search.set_keywords(keywords=organizations)
shodan_search.search_cve()