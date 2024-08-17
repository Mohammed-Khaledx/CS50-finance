from cs50 import SQL
from helpers import lookup ,usd
from datetime import datetime
import pytz

db = SQL("sqlite:///finance.db")
nows = datetime.now(pytz.timezone('Africa/Cairo'))
f= nows.strftime("%d/%m/%Y %H:%M:%S")
t=db.execute("SELECT datetime(?)" ,nows )
    
# db.exucute

# x= SELECT datetime(nows)
print(f)


# done =1
# if done:
#     print("DONE\n")
    
#     print(usd(1255.900000002))

db.execute("DROP TABLE history" )

# cash = db.execute("SELECT cash FROM users WHERE id = 1")
# user = db.execute("SELECT username FROM users WHERE id = 1")
# info = lookup("AMZN")


# print (int(info["price"]))

