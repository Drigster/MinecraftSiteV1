import json
from datetime import datetime

from sweater import app

@app.template_filter()
def dict(string):
	if string == None:
		return {}
	return json.loads(string)

@app.template_filter()
def date(date, format, output_format):
	time = datetime.strptime(date, format)
	return time.strftime(output_format)

@app.template_filter()
def index(list, index):
	return list[index]