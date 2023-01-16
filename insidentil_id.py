import shodan, math, sqlite3
from datetime import datetime
from elasticsearch import Elasticsearch

class shodan_search:
    def __init__(self,api_key):
        self.API_KEY=api_key        
        self.api = shodan.Shodan(self.API_KEY)        
        self.results = []
        self.all_result = []
        self.keyword = ""
        self.keywords = []
        self.FACETS = [('vuln',1000)]
        self.conn = sqlite3.connect('insidentil.db')
        self.cur = self.conn.cursor()

    def set_database(self):
        self.conn.execute('''CREATE TABLE IF NOT EXISTS cve_organization_result_tb\
        (id INTEGER PRIMARY KEY AUTOINCREMENT, organization_keyword text not null, year int, month int, total_cve int, status char(20));''')
        ### STATUS INIT PROCCESS DONE
        self.conn.execute('''CREATE TABLE IF NOT EXISTS cve_search_result_tb\
        (id INTEGER PRIMARY KEY AUTOINCREMENT, organization_keyword text not null, keyword text not null, cve text not null, year int, month int, total_search int, page int, total_page int, status char(20));''')
        ### STATUS INIT PROCCESS DONE

    def set_elasticsearch_auth(self, ip_address, username, password):
        self.es = Elasticsearch(ip_address,verify_certs=False,basic_auth=(username,password))

    def set_keyword(self,keyword):
        self.keyword=keyword
        
    def set_keywords(self,keywords):
        self.keywords=keywords

    ### CVE Search
    def search_cve(self):
        self.init_cve()
        self.get_cve_number_page()
        self.get_cve_data()

    def get_cve_data(self):
        date_now = datetime.now().strftime("%Y-%m-%d")
        cursor = self.conn.execute("SELECT * from cve_search_result_tb WHERE status = 'proccess'")
        rows = cursor.fetchall() 
        no = 0
        total = len(rows)
        for row in rows:
            this_id = row[0]
            this_page = row[7]
            this_total_page = row[8]
            this_keyword = row[2]
            this_cve = row[3]
            while(this_page<this_total_page):
                print("Processing "+str(no+1)+"/"+str(total)+" [Preprocessing "+str(this_page+1)+"/"+str(this_total_page)+"]")
                results = self.api.search(this_keyword,page=this_page)
                for i in results['matches']:
                    hasil={}
                    output = {}
                    for k in i['vulns']:
                        vulner=k
                    score = i['vulns'][this_cve.upper()]['cvss']
                    if ( 3.9 >= score >=0.1 ):
                        category = "LOW"
                    elif (6.9 >= score >= 4.0):
                        category = "MEDIUM"
                    elif (8.9 >= score >= 7.0):
                        category = "HIGH"
                    elif (10 >= score >= 9.0):
                        category = "CRITICAL"
                    else :
                        category = "-"
                    output['hostnames'] = str(i["hostnames"]).replace("[","").replace("]","")
                    output['timestamp'] = i['timestamp']
                    output['isp'] =  i['isp']
                    output['city'] = i["location"]['city']
                    output['org'] = str(i["org"])
                    output['cve'] = this_cve.upper()
                    output['score'] = str(score)
                    output['category'] = category
                    output['ip'] = str(i['ip_str'])
                    output['timestamp_crawling'] = datetime.now()
                    self.es.index(index="crawling_cve-"+date_now,document=output)
                    # print(output)
                this_page = this_page+1
            # print("crawling_cve-"+date_now)
            self.conn.execute("UPDATE cve_search_result_tb set page=?, status=? where id = ?",(this_page, "done", this_id))
            self.conn.commit()
            no = no+1

    def get_cve_number_page(self):
        cursor = self.conn.execute("SELECT * from cve_search_result_tb WHERE status is null")
        rows = cursor.fetchall() 
        no = 0
        total = len(rows)
        for row in rows:
            print(str(no)+"/"+str(total))
            this_id = row[0]
            this_query = row[2]
            this_cve = row[3]
            results=self.api.search(this_query)
            this_total_search = results['total']
            this_total_page=math.ceil(results['total']/100)
            self.conn.execute("UPDATE cve_search_result_tb set total_search = ?, page=?, total_page = ?, status =? where id = ?",(this_total_search, 0, this_total_page, "proccess", this_id))
            self.conn.commit()
            no = no+1


    def init_cve(self):
        this_month = datetime.now().month
        this_year = datetime.now().year
        for query in self.keywords:
            # self.cur.execute("SELECT id FROM cve_organization_result_tb WHERE organization_keyword = ? AND year = ? AND month =?",(query, this_year, this_month))
            self.cur.execute("SELECT id FROM cve_organization_result_tb WHERE organization_keyword = ? AND year = ? AND month =?",(query, this_year, this_month))
            db_result=self.cur.fetchall()
            # print(len(db_result))
            if len(db_result)==0:
                # print("hai ini ke print")
                list_cve = self.api.search(query,facets=self.FACETS)
                for this_result in list_cve['facets']['vuln']:
                    this_query=query+' vuln:"'+this_result['value']+'"'
                    # self.conn.execute("INSERT INTO cve_search_result_tb(keyword,year,month) VALUES (?,?,?)",(this_query, this_year, this_month))
                    self.conn.execute("INSERT INTO cve_search_result_tb(keyword,year,month,organization_keyword,cve) \
                    SELECT ?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM cve_search_result_tb WHERE keyword = ? AND year = ? AND month =?)",(this_query, this_year, this_month,query, this_result['value'],this_query, this_year, this_month))
                total_cve = len(list_cve['facets']['vuln'])
                self.conn.execute("INSERT INTO cve_organization_result_tb(organization_keyword,year,month, total_cve, status) \
                SELECT ?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM cve_organization_result_tb WHERE organization_keyword = ? AND year = ? AND month =?)",(query, this_year, this_month, total_cve, "init", query, this_year, this_month))
        print("organization data updated") 
        with self.conn:
            # self.cur.execute("SELECT * FROM cve_search_result_tb")
            # print(self.cur.fetchall())
            self.cur.execute("SELECT * FROM cve_organization_result_tb")
            self.cur.fetchall()  
    
