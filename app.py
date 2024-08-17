#TODO:time format in history and buy 
#FIXME: usd format


import os

from cs50 import SQL
from datetime import datetime
# from datetime.datetime import strftime
# from datetime import datetime,strftime

import pytz
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    #creating table of process
    db.execute(
            "CREATE TABLE IF NOT EXISTS process (user_id INTEGER, symbol TEXT, name TEXT, price REAL, share INTEGER, total REAL , time TEXT)")

    # this dict for the updated price of each symbol
    info_dict = {}
    sdict = []
    # here is a query for every process has the user done
    processes = db.execute(
        "SELECT * FROM process WHERE user_id = ?", session.get('user_id'))
    
        
    Total = 0
    for process in processes:
        # query the API for prices changes
        info = lookup(process["symbol"])
        process["new_price"] = [info["price"], process["share"]]
        
        if not info:
            return apology("network error")

        #collect the totals
        Total = Total + process["new_price"][0] * process["new_price"][1]
        sdict.append(process)

    # get the balance.new_price of the user
    cash = db.execute("SELECT cash FROM users WHERE id = ?",session.get("user_id"))
    cash = cash[0]
    cash = cash["cash"]
    Total = usd(cash + Total)


    
    return render_template('index.html', processes = sdict, prices=info_dict, cash = usd(cash),Total = Total)
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # check if process done

    done = 0

    if request.method == "POST":

        shares = request.form.get("shares")

        symbol = request.form.get("symbol")

        if not symbol:
            return apology("provide a symbol")

        if not shares:
            return apology("missing the number of shares")
        if float(shares) <= 0:
            return apology("provide a positive number for shares")

        info = lookup(symbol)
        if info == None:
            return apology("there is no data for this symbol")

        # calculating the price of shared stocks
        total_price = float(info["price"]) * float(shares)
        # getting the cash balance of the user
        user_cash_dict = db.execute(
            "SELECT cash FROM users WHERE id = ?", session.get("user_id"))

        for balance in user_cash_dict:
            cash = balance["cash"]

        if float(total_price) > float(cash):
            return apology("Not enough cash")

        # calculating the updated cash balance
        updated_cash = float(cash) - total_price

        # creating a new table for more information about the process
        # table columns: id of th user : username: company symbol : price of stock
        # : shares amount : total price : time of the process
        db.execute(
            "CREATE TABLE IF NOT EXISTS process (user_id INTEGER, symbol TEXT, name TEXT, price REAL, share INTEGER, total REAL , time TEXT)")

        symbol_dict = db.execute("SELECT symbol FROM process WHERE user_id = ?", session.get("user_id"))

        flag = 0
        nows = datetime.now(pytz.timezone('Africa/Cairo'))
        # nows = nows.strftime('%Y%m%d%H:%M:%S')
        if not symbol_dict:
            # inserting the information of the process
            #FIXME: time format
            db.execute("INSERT INTO process (user_id, symbol,name, price, share, total , time) VALUES(?,?,?,?,?,?,?)",session.get("user_id"), info["symbol"],info["name"], info["price"], shares, total_price, nows)
            flag = 1        
        for f_symbol in symbol_dict:

            if symbol.upper() == f_symbol["symbol"]:

                db.execute("UPDATE process SET share  = share + ?, total = total + ?   WHERE user_id = ? AND symbol = ? ",shares, total_price, session.get('user_id'), symbol.upper())

                flag = 1
                break

        if flag == 0:
            # inserting the information of the process
            #FIXME: time format
            db.execute("INSERT INTO process (user_id, symbol,name, price, share, total , time) VALUES(?,?,?,?,?,?,?)",session.get("user_id"), info["symbol"],info["name"], info["price"], shares, total_price, nows)
            
            flag = 1

        if flag == 1:
            # update the balance of the user
            db.execute("UPDATE users SET cash  = ? WHERE id = ?",
                    updated_cash, session.get("user_id"))
            done = 1
        
        if done:
            # add this transaction to the history table
            db.execute("CREATE TABLE IF NOT EXISTS history (user_id INTEGER,symbol TEXT,shares INTEGER,price REAL, date TEXT)")
            #FIXME: time format
            ok = db.execute("INSERT INTO history (user_id,symbol,shares,price,date) VALUES(?,?,?,?,?)",session.get("user_id"),symbol.upper(),shares,info["price"],nows)
        if not ok:
            flash("Something went wrong" , "error")
            return render_template("buy.html")
        else:
            # Redirect user to home page
            return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    #create the table of histories if not exist
    db.execute("CREATE TABLE IF NOT EXISTS history (user_id INTEGER,symbol TEXT,shares INTEGER,price REAL, date TEXT)")
    history = db.execute("SELECT symbol,shares,price,date FROM history WHERE user_id = ?" , session.get("user_id") )
    return render_template("history.html" ,history =history )
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?",request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("you must provide a symbol")

        info = lookup(symbol)
        if info == None:
            return apology("there is no data for this symbol")
        else:
            return render_template("quoted.html", compName=info["name"], compSymbol=info["name"], price=info["price"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        done = 1
        # get the data from the form
        userName = request.form.get("username")
        password = request.form.get("password")

        # Ensure username was submitted
        if not userName:
            return apology("must provide username", 403)

        # Ensure username was submitted
        if not password:
            return apology("must provide a password", 403)


        # ensure the two passwords are equal
        if password != request.form.get("confirmation"):
            return apology("passwords do not match", 403)


        SpecialSym =['$', '@', '#', '%']
        val = True
        
        if len(password) < 8:
            flash('length should be at least 8' , "error")
            val = False
            
        if len(password) > 20:
            flash('length should be not be greater than 8' , "error")
            val = False
            
        if not any(char.isdigit() for char in password):
            flash('Password should have at least one numeral' , "error")
            val = False
            
        if not any(char.isupper() for char in password):
            flash('Password should have at least one uppercase letter' , "error")
            val = False
            
        if not any(char.islower() for char in password):
            flash('Password should have at least one lowercase letter' , "error")
            val = False
            
        if not any(char in SpecialSym for char in password):
            flash('Password should have at least one of the symbols $@#' , "error")
            val = False
        if not val:
            return redirect("/register")

        # Ensure username was submitted
        if not request.form.get("confirmation"):
            return apology("confirm your password", 403)

        # get all usernames in my database
        users = db.execute("SELECT username FROM users")

        # Ensure username doesn't already exist
        for user in users:
            if userName == user["username"]:
                return apology("user name already exist", 403)

        # hash the password to store it in the database
        hashed_password = generate_password_hash(password)

        ok = db.execute("INSERT INTO users (username, hash) VALUES (?,?)",userName, hashed_password)
        if not ok:
            done = 0
        
        # check that everything is ok
        if done:
            flash('Registered!', 'success') # flash a success message    
            return render_template("login.html")
        else:
            flash('Failed!', 'error') # flash a success message  
            return render_template("register.html")  

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        all_is_ok = 1
        done = 0

        nows = datetime.now(pytz.timezone('Africa/Cairo'))

        symbol = request.form.get("value")
        shares = request.form.get("shares")

        # query for what the user already have
        symbol_list = db.execute("SELECT symbol,share FROM process WHERE user_id = ? AND symbol = ?", session.get('user_id') , symbol)

        if not symbol or not symbol_list:
            return apology("select a correct symbol")
        
        for data in symbol_list:
            if int(shares) > data["share"]:
                return apology("There is not enough shares")
            #if this is the last stock that user has
            #it will be deleted    
            if int(shares) == data["share"]:
                db.execute("DELETE FROM process WHERE user_id = ? AND symbol = ?" , session.get("user_id") , symbol)
                flag = 1
            else:    
                db.execute("UPDATE process SET share = share - ? WHERE user_id = ? AND symbol = ?",shares,session.get("user_id") , symbol)
                flag = 1
        info  = lookup(symbol)
        if flag == 1:
            price = info["price"]
            total_price = float(price) * float(shares)
            db.execute("UPDATE users SET cash = cash + ? WHERE id = ?",total_price,session.get("user_id"))
            done = flag
        
        if done:
            # add this transaction to the history table
            db.execute("CREATE TABLE IF NOT EXISTS history (user_id INTEGER,symbol TEXT,shares INTEGER,price REAL, date TEXT)")
            negative = int(shares) * -1
            now = datetime.now(pytz.timezone('Africa/Cairo'))

            ok = db.execute("INSERT INTO history (user_id,symbol,shares,price,date) VALUES(?,?,?,?,?)",session.get("user_id"),symbol.upper(),negative,info["price"],now)
            if not ok:
                all_is_ok = 0
        # check that everything is ok
        if all_is_ok:
            flash('Sold!', 'success') # flash a success message    
            return redirect("/")
        else:
            flash('Something went wrong! ', 'error') # flash a error message
            return redirect("/")
    else:

        symbols = db.execute(
            "SELECT symbol FROM process WHERE user_id = ?", session.get("user_id"))
        return render_template("sell.html", symbols=symbols)
