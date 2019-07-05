
## all required import libraries
from flask import Flask, render_template, request, jsonify, redirect, session, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from flask_login import UserMixin
from flask_login import current_user, login_user
from flask_login import LoginManager
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

from requests_oauth2.services import GoogleClient
from requests_oauth2 import OAuth2BearerToken
import dateutil.parser
import datetime
import requests
import json
import ast
import os

###initial configuration
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(20)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
auth = HTTPBasicAuth()
login = LoginManager(app)
Session = {}
A = {}
@app.route('/showall/')
def show_all():
    return render_template('show.html',results = POIS.query.all())

@app.route('/')
def home():
    if current_user.is_authenticated:
        user = True
        return render_template('index.html', user=user)
    else:
        return render_template('index.html')

@app.route('/about/')
def about():
    return render_template('about.html')




@app.route('/blog/')
def blog():
    return render_template('blog.html')

@app.route('/car/')
def car():
    return render_template('car.html')

@app.route('/contact/')
def contact():
    return render_template('contact.html')

@app.route('/services/')
def services():
    return render_template('services.html')

@app.route('/plan/')
def plan():
    return render_template('plan.html')

@app.route('/signin/')
def signin():
    register = RegistrationForm()
    form = LoginForm()
    return render_template('signin.html',form = form, register= register )

@app.route('/signin/')
def header():
    return render_template('signin.html')

@app.route('/result/')
def result():
    if current_user.is_authenticated:
        user = True
        return render_template('result.html', user=true)
    else:
        return render_template('result.html')


@app.route('/places/')
def places():
    if current_user.is_authenticated:
        user = True
        return render_template('places.html', user=user)
    else:
        return render_template('places.html')

@app.route('/place_detail/')
def place_detail():
    return render_template('place_detail.html')

@app.route('/maps/')
def maps():
    return render_template('maps.html')

@app.route('/food_places/')
def food_places():
    return render_template('food_places.html')

@app.route('/hotel_page/')
def hotel_page():
    return render_template('hotel_page.html')

# @app.route('/Mytrip/')
# def my_trip():
#     if current_user.is_authenticated:
#         user = True
#         return render_template('MyTrip.html', user=user)
#     else:
#         return render_template('MyTrip.html')

@app.route('/logout/')
def logout():
    return render_template('index.html')

# flight search
@app.route('/response',methods = ['POST', 'GET'])
def response():
    if request.method == 'POST':
        result = request.form
        date_start = result['date-start']
        date_end = result['date-end']
        fro = result['from']
        to = result['to']
        params = {'to':to, 'from':fro, 'date_start':date_start, 'date_end': date_end}
        r = requests.get('http://127.0.0.1:5000/apis/flight_process', params=params)
        r1= r.json()['result']
        r2 = r.json()['data']
        if Session['id'] :
             return render_template('result.html', results=r1, data=r2,user = Session['id'])
        return render_template('result.html', results=r1, data=r2)

# hotel search
@app.route('/response_hotel',methods = ['POST', 'GET'])
def response_hotel():
    if request.method == 'POST':
        result = request.form
        dict_1 = {}
        dict_1['city'] = result['city']
        dict_1['date_start'] = result['date-start']
        dict_1['date_end'] = result['date-end']
        dict_1['adults'] = result['adults']
        dict_1['children'] = result['children']
        dict_1['rooms'] = result['rooms']
        dict_1['price'] = result['price']
        params = {'city':result['city'], 'check_in':result['date-start'], 'check_out':result['date-end'], 'adults':result['adults'], 'children':result['children'], 'rooms':result['rooms'], 'price':result['price']}
        r = requests.get('http://127.0.0.1:5000/apis/hotel_process', params=params)
        r = r.json()['result']
        return render_template('hotel_page.html', results=r, data=dict_1)

# hotel details
@app.route('/hotel_details',methods = ['POST', 'GET'])
def hotel_details():
	if request.method == 'POST':
		resultt = request.form
		result = ast.literal_eval(resultt['data'])
		hotel = resultt['name']
		photo_ref = resultt['photo']
		params = {'city':result['city'], 'check_in':result['date_start'], 'check_out':result['date_end'], 'adults':result['adults'], 'children':result['children'], 'rooms':result['rooms'], 'price':result['price'], 'details':'true', 'hotel':hotel}
		r = requests.get('http://127.0.0.1:5000/apis/hotel_process', params=params)
		r = r.json()['result']
		return render_template('hotel_detail.html', results=r, photo_ref=photo_ref)


@app.route('/poi',methods = ['POST', 'GET'])
def poi():
    if request.method == 'POST':
        result = request.form
        lst = result['place']
        query = 'http://127.0.0.1:5000/apis/places?city='+str(lst)
        r = requests.get(query)
        r = r.json()['result']
        if current_user.is_authenticated:
            if Session['id']:
                return render_template('places.html', results=r, user = Session['id'])
        return render_template('places.html', results=r)


@app.route('/pl',methods = ['POST', 'GET'])
def pl():
    if current_user.is_authenticated:
        user=True
    if request.form['action'] == 'view':
        try:
        # if request.method == 'POST':
            result = request.form
            name = str(result['name'])
            lat = str(result['lat'])
            lng = str(result['lng'])
            params = {'name':name, 'lat':lat, 'lng':lng}
            r = requests.get('http://127.0.0.1:5000/apis/place_detail', params=params)
            r = r.json()['result']
        except:
            print('description not found')
        return render_template('place_detail.html', results=r)

    elif request.form['action'] == 'save':
        res = request.form.getlist("places")
        import ast
        res = ast.literal_eval(res[0])
        name = res['name']
        rating = res['rating']
        address = res['formatted_address']
        # for item in res:
        # num_rows_deleted = db.session.query(POIS).delete()
        # db.session.commit()
        if A['user'] == True:
            Places = POIS(place=name, rating=rating, address=address,user_id=Session['id'])
            db.session.add(Places)
            db.session.commit()
            rr = []
            food = []
            for row in db.session.query(POIS).filter_by(user_id=Session['id']).all():
                dict_new = {}
                dict_new['place'] = row.place
                dict_new['rating'] = row.rating
                dict_new['address'] = row.address
                rr.append(dict_new)
            ff = []
            for row in db.session.query(FOODS).filter_by(user_id=Session['id']).all():
                dict_new = {}
                dict_new['place'] = row.place
                dict_new['rating'] = row.rating
                dict_new['address'] = row.address
                dict_new['price'] = row.price
                ff.append(dict_new)
        else:
            Places = POIS(place=name, rating=rating, address=address, user_gid=Session['id'])
            db.session.add(Places)
            db.session.commit()
            rr = []
            food = []
            for row in db.session.query(POIS).filter_by(user_gid=Session['id']).all():
                dict_new = {}
                dict_new['place'] = row.place
                dict_new['rating'] = row.rating
                dict_new['address'] = row.address
                rr.append(dict_new)
            ff = []
            for row in db.session.query(FOODS).filter_by(user_gid=Session['id']).all():
                dict_new = {}
                dict_new['place'] = row.place
                dict_new['rating'] = row.rating
                dict_new['address'] = row.address
                dict_new['price'] = row.price
                ff.append(dict_new)
        # results =
    return redirect("/MyTrip")


# service 8 db
@app.route('/apis/dbase/user', methods = ['POST', 'GET', 'PUT', 'DELETE'])
def dbase():
	if request.method == 'POST':
		args = request.args.to_dict()
		name = args['name']
		email = args['email']
		password = args['password']
		User = Users(name=name, email=email)
		User.set_password(password)
		db.session.add(User)
		db.session.commit()
		ff = db.session.query(Users).filter_by(name=name).one()
		return jsonify({'result': ff.id})

	if request.method == 'GET':
		args = request.args.to_dict()
		idd = args['id']
		ff = db.session.query(Users).filter_by(id=idd).one()
		dict_nn = {}
		dict_nn['id']	= ff.id
		dict_nn['name']	= ff.name
		dict_nn['email']	= ff.email
		return jsonify({'result': dict_nn})
	if request.method == 'DELETE':
		args = request.args.to_dict()
		idd = args['id']
		ff = Users.query.filter_by(id=idd).one()
		db.session.delete(ff)
		db.session.commit()
		st = 'user '+ idd+ ' deleted'
		return jsonify({'result': st})

# service 9 db
@app.route('/apis/dbase/mytrips', methods = ['POST', 'GET', 'PUT', 'DELETE'])
def mytrips():
	if request.method == 'POST':
		args = request.args.to_dict()
		name = args['place']
		rating = args['rating']
		address = args['address']
		user_id = args['user_id']
		Places = POIS(place=name, rating=rating, address=address, user_id=user_id)
		db.session.add(Places)
		db.session.commit()
		ff = db.session.query(POIS).filter_by(place=name).order_by(POIS.id.desc()).first()
		dict_nn = {}
		dict_nn['id']	= ff.id
		dict_nn['place']	= ff.place
		dict_nn['rating']	= ff.rating
		dict_nn['address']	= ff.address
		dict_nn['user_id']	= ff.user_id
		return jsonify({'result': dict_nn})

	if request.method == 'GET':
		args = request.args.to_dict()
		idd = args['user_id']
		rr = []
		for ff in db.session.query(POIS).filter_by(user_id=idd).all():
			dict_nn = {}
			dict_nn['place_id']	= ff.id
			dict_nn['place']	= ff.place
			dict_nn['rating']	= ff.rating
			dict_nn['address']	= ff.address
			rr.append(dict_nn)
		return jsonify({'result': rr})
	if request.method == 'DELETE':
		args = request.args.to_dict()
		idd = args['place_id']
		ff = POIS.query.filter_by(id=idd).one()
		db.session.delete(ff)
		db.session.commit()
		st = 'place '+ idd+ ' deleted'
		return jsonify({'result': st})
		


# service 10 foodsave
@app.route('/apis/dbase/foodd', methods = ['POST', 'GET', 'PUT', 'DELETE'])
def foodd():
	if request.method == 'POST':
		args = request.args.to_dict()
		name = args['place']
		rating = args['rating']
		address = args['address']
		price = args['price']
		user_id = args['user_id']
		Food = FOODS(place=name, rating=rating, address=address, price=price,  user_id=user_id)
		db.session.add(Food)
		db.session.commit()
		ff = db.session.query(FOODS).filter_by(place=name).order_by(FOODS.id.desc()).first()
		dict_nn = {}
		dict_nn['id']	= ff.id
		dict_nn['place']	= ff.place
		dict_nn['rating']	= ff.rating
		dict_nn['address']	= ff.address
		dict_nn['price']	= ff.price
		dict_nn['user_id']	= ff.user_id
		return jsonify({'result': dict_nn})

	if request.method == 'GET':
		args = request.args.to_dict()
		idd = args['user_id']
		rr = []
		for ff in db.session.query(FOODS).filter_by(user_id=idd).all():
			dict_nn = {}
			dict_nn['food_id']	= ff.id
			dict_nn['place']	= ff.place
			dict_nn['rating']	= ff.rating
			dict_nn['price']	= ff.price
			dict_nn['address']	= ff.address
			rr.append(dict_nn)
		return jsonify({'result': rr})
	if request.method == 'DELETE':
		args = request.args.to_dict()
		idd = args['food_id']
		ff = FOODS.query.filter_by(id=idd).one()
		db.session.delete(ff)
		db.session.commit()
		st = 'food place'+ idd+ ' deleted'
		return jsonify({'result': st})
		


	# 	db.session.add(Places)
	# 	db.session.commit()
	# if request.method == 'GET':
	# 	city = args['city']
	# if request.method == 'DELETE':
	# 	city = args['city']
	# if request.method == 'PUT':
	# 	city = args['city']
	# args = request.args.to_dict()
	# city = args['city']
	# params = {'key':'Key', 'address':city}
	# r = requests.get('https://maps.googleapis.com/maps/api/geocode/json', params=params)
	# r = r.json()['results'][0]['geometry']['location']
	# return jsonify({'result': r})




@app.route('/mp',methods = ['POST', 'GET'])
def mp():
	try:
		if request.method == 'POST':
			result = request.form
			result_list = ast.literal_eval(result['name'])
	except:
		print('description not found')
	return render_template('maps.html', stationss=result_list)

# food
@app.route('/food',methods = ['POST', 'GET'])
def food():
    if request.method == 'POST':
        result = request.form
        place = result.get('place')
        check = result.getlist('check')
        bars = ''
        restaurants = ''
        fast_foods = ''
        for item in check:
            if item == 'bars':
                bars = 'bars'
            if item == 'restaurants':
                restaurants = 'restaurants'
            if item == 'fast_foods':
                fast_foods = 'fast_foods'

        params = {'city':place, 'bars':bars, 'restaurants':restaurants, 'fast_foods':fast_foods}
        r = requests.get('http://127.0.0.1:5000/apis/food_options', params=params )
        r = r.json()['result']
        if current_user.is_authenticated :
            if Session['id'] :
                return render_template('food.html', results=r, place=place,user = Session['id'])
        return render_template('food.html', results=r, place=place)


@app.route('/food_map',methods = ['POST', 'GET'])
def food_map():
    if current_user.is_authenticated:
        user=True
    if request.form['action'] == 'view map':
        result = request.form
        loc_dict = {}
        place = str(result['name'])
        loc_dict['lat'] = str(result['lat'])
        loc_dict['lng'] = str(result['lng'])
        place = str(result['name'])
        return render_template('food_places.html', results=loc_dict)

    elif request.form['action'] == 'save':
        # res = {}
        res = request.form.getlist("food")
        import ast
        res = ast.literal_eval(res[0])
        name = res['name']
        rating = res['rating']
        address = res['formatted_address']
        price = res['price']
        # for item in res:
        # num_rows_deleted = db.session.query(POIS).delete()
        # db.session.commit()
        if A['user'] == True:
            Food = FOODS(place=name, rating=rating, address=address,price=price, user_id=Session['id'])
            db.session.add(Food)
            db.session.commit()

            rr = []
            for row in db.session.query(POIS).filter_by(user_id=Session['id']).all():
                dict_new = {}
                dict_new['place'] = row.place
                dict_new['rating'] = row.rating
                dict_new['address'] = row.address
                rr.append(dict_new)
            ff = []
            for row in db.session.query(FOODS).filter_by(user_id=Session['id']).all():
                dict_new = {}
                dict_new['place'] = row.place
                dict_new['rating'] = row.rating
                dict_new['address'] = row.address
                dict_new['price'] = row.price
                ff.append(dict_new)
        else:
            Food = FOODS(place=name, rating=rating, address=address,price=price, user_gid=Session['id'])
            db.session.add(Food)
            db.session.commit()
            rr = []
            for row in db.session.query(POIS).filter_by(user_gid=Session['id']).all():
                dict_new = {}
                dict_new['place'] = row.place
                dict_new['rating'] = row.rating
                dict_new['address'] = row.address
                rr.append(dict_new)
            ff = []
            for row in db.session.query(FOODS).filter_by(user_gid=Session['id']).all():
                dict_new = {}
                dict_new['place'] = row.place
                dict_new['rating'] = row.rating
                dict_new['address'] = row.address
                dict_new['price'] = row.price
                ff.append(dict_new)
                            # results =
    return redirect("/MyTrip")


@app.route('/dell',methods = ['POST', 'GET'])
def dell():
    if current_user.is_authenticated:
        user=True
    if request.form['action'] == 'del_place':
        res = request.form.getlist("places")
        import ast
        res = ast.literal_eval(res[0])
        # place = res['place']
        address = res['address']
        # for item in res:
        # num_rows_deleted = db.session.query(POIS).delete()
        # db.session.commit()
        Places = POIS.query.filter_by(address=address).one()
        # POIS.query.filter_by(address=address).delete()
        db.session.delete(Places)
        db.session.commit()

    elif request.form['action'] == 'del_food':
        # res = {}
        res = request.form.getlist("food")
        import ast
        res = ast.literal_eval(res[0])
        # name = res['name']
        address = res['address']
        # for item in res:
        # num_rows_deleted = db.session.query(POIS).delete()
        # db.session.commit()
        Food = FOODS.query.filter_by(address=address).one()
        # Food = FOODS.query.filter_by(address=address).delete()
        db.session.delete(Food)
        db.session.commit()
    return redirect("/MyTrip")


#authentication
@app.route('/signin/sign_up',methods = ['POST','GET'])
def sign1up():
    if request.method == 'GET':
        return render_template('signin.html')
    register = RegistrationForm()
    form = LoginForm()
    users = Users(email=register.email.data,name=register.firstname.data)
    users.set_password(register.password.data)
    db.session.add(users)
    db.session.commit()
    return render_template('signin.html',form = form, register = register)

@app.route('/sign_in',methods = ['POST','GET'])
def sign1_in():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    register = RegistrationForm()
    users = Users.query.filter_by(email=form.email.data).first()
    if users is None or not users.check_password(form.password.data):
        return redirect(url_for('signin'))
    users.authenticated = True
    g.user = users
    login_user(users)
    Session['id'] = users.id
    A['user']= True
    return render_template('index.html', form = form, register = register, user = True)


# rauth OAuth 2.0 service wrapper
google_auth = GoogleClient(
        client_id=("client_id"
                   ".apps.googleusercontent.com"),
        client_secret="secret",
        redirect_uri="http://localhost:5000/google/oauth2callback",
)
@app.route('/signin/signup_with_google')
def index():
    return redirect("/google/")
@app.route("/google/")
def google_index():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if not session.get("access_token"):
        return redirect("/google/oauth2callback")
    with requests.Session() as s:
        s.auth = OAuth2BearerToken(session["access_token"])
        r = s.get("https://www.googleapis.com/plus/v1/people/me")
    r.raise_for_status()
    data = r.json()
    name = str(data.get("name"))
    email = str(data.get("email"))
    user = Usergoogle.query.filter_by(email=Usergoogle.email).first()
    Session['name'] = name
    #user.authenticated = True
    if user is None:
        user = Usergoogle(email=email,name=name)
        g.user = user
        db.session.add(user)
        db.session.commit()
        app.logger.info(user.id)
    login_user(user)
    Session['id'] = user.id
    A['user']= False
    return render_template('index.html',user = True)


@app.route("/google/oauth2callback")
def google_oauth2callback():
    code = request.args.get("code")
    error = request.args.get("error")
    if error:
        return "error :( {!r}".format(error)
    if not code:
        return redirect(google_auth.authorize_url(
            scope=["profile", "email"],
            response_type="code",
        ))
    data = google_auth.get_token(
        code=code,
        grant_type="authorization_code",
    )
    session["access_token"] = data.get("access_token")
    return redirect("/google/")


#logout from the Session
@app.route('/logout')
def log_out():
   # remove the username from the session if it is there
   user = current_user
   user.authenticated = False
   g.user = null
   logout_user()
   return redirect('http://127.0.0.1:5000')

@login.user_loader  #unique identifier for Flask's user session
def load_user(id):
    if A['user'] == True:
        return Users.query.get(int(id))
    else:
        return Usergoogle.query.get(int(id))

#my trip hotel_details
@app.route('/MyTrip',methods = ['POST','GET'])
def mytrip():
    if current_user.is_authenticated:
        user= True
    if A['user'] == True:
        rr = []
        for row in db.session.query(POIS).filter_by(user_id=Session['id']).all():
            dict_new = {}
            dict_new['place'] = row.place
            dict_new['rating'] = row.rating
            dict_new['address'] = row.address
            rr.append(dict_new)
        ff = []
        for row in db.session.query(FOODS).filter_by(user_id=Session['id']).all():
            dict_new = {}
            dict_new['place'] = row.place
            dict_new['rating'] = row.rating
            dict_new['address'] = row.address
            dict_new['price'] = row.price
            ff.append(dict_new)
    else:
        rr = []
        for row in db.session.query(POIS).filter_by(user_gid=Session['id']).all():
            dict_new = {}
            dict_new['place'] = row.place
            dict_new['rating'] = row.rating
            dict_new['address'] = row.address
            rr.append(dict_new)
        ff = []
        for row in db.session.query(FOODS).filter_by(user_gid=Session['id']).all():
            dict_new = {}
            dict_new['place'] = row.place
            dict_new['rating'] = row.rating
            dict_new['address'] = row.address
            dict_new['price'] = row.price
            ff.append(dict_new)
    return render_template('MyTrip.html', food=ff, place=rr,user=user)

#process_centric services

# service 1 flight process
@app.route('/apis/flight_process', methods=['GET'])
def get_flight_process():
	args = request.args.to_dict()
	resp_list = []
	resp_dict = {}
	to = args['to']
	fro = args['from']
	date_start = args['date_start']
	date_end = args['date_end']
	params = {'to':to, 'from':fro}
	r1 = requests.get('http://127.0.0.1:5000/apis/iata_code', params=params)
	r1= r1.json()['result']
	params2 = {'from':r1['from'], 'to':r1['to'], 'date_start':date_start, 'date_end':date_end}
	r = requests.get('http://127.0.0.1:5000/apis/sort', params=params2)
	r = r.json()['result']
	for res in r:
		airlineCode = res['airlineCode']
		res['logo'] = "http://pics.avs.io/50/50/"+airlineCode+".png"
		params = {'airlineCode':airlineCode}
		r2 = requests.get('http://localhost:5000/apis/airline_link', params=params)
		res['airline_link'] = r2.json()['result']['airline_link']
		r3 = requests.get('http://localhost:5000/apis/airline_name', params=params)
		res['airline'] = r3.json()['result']['airline']
		# resp_list.append(resp_dict)
	resp_dict['to'] = to
	resp_dict['from'] = fro
	resp_dict['date-start'] = date_start
	resp_dict['date_end'] = date_end
	return jsonify({'result': r, 'data':resp_dict})

# service 2 hotel process
@app.route('/apis/hotel_process', methods=['GET'])
def get_hotel_process():
	args = request.args.to_dict()
	city = args['city']
	adults = args['adults']
	date_start = args['check_in']
	date_end = args['check_out']
	children = args['children']
	price = args['price']
	rooms = args['rooms']
	details = request.args.get('details', default = 'false', type = str)
	hotel = request.args.get('hotel', default = '', type = str)
	query = 'http://127.0.0.1:5000/apis/geocoding?city='+str(city)
	r = requests.get(query)
	r = r.json()['result']
	params = {'lat':r['lat'], 'lng':r['lng'], 'check_in':date_start, 'check_out':date_end, 'adults':adults, 'children':children, 'rooms':rooms, 'price_range':price, 'details':details, 'hotel':hotel}
	r2 = requests.get('http://127.0.0.1:5000/apis/hotel_list', params=params)
	r2 = r2.json()['result']
	return jsonify({'result': r2})

#service 3  new user signup,signin and google authentication
@app.route('/apis/signup', methods=['POST'])
def sign_up():
    args = request.args
    username = args['username']
    password = args['password']
    email = args['email']
    user = User(username=username, password=password, email=email)
    db.session.add(user)
    db.session.commit()
    return jsonify({
        'response': 'User created successfully','username':username
    })
@app.route('/apis/signin',methods=['GET'])
def sign_in():
    args=request.args
    un=args['username']
    pas=args['password']
    user = User.query.filter_by(username=username).first()
    if user is not None:
        if pas==user.password:
          return jsonify({"status":'successfully logged in','username':u},200)
        else:
           return jsonify({'message':'wrong password'},204)
    else:
        return jsonify({'message':'username not found'},203)




#####################################################################################################
# business logic layer

# service 1 flight logic 1
@app.route('/apis/iata_code', methods=['GET'])
def get_iata_code():
	loc_dict = {}
	args = request.args.to_dict()
	loc_dict['to'] = args['to'][:3]
	loc_dict['from']=args['from'][:3]
	return jsonify({'result': loc_dict})

# service 2 flight logic 2
@app.route('/apis/sort', methods=['GET'])
def get_sort():
	# loc_dict = {}
	args = request.args.to_dict()
	to = args['to']
	fro =args['from']
	date_start = args['date_start']
	date_end = args['date_end']
	sort_by = request.args.get('sort_by', default = 'price', type = str)
	asc = request.args.get('asc', default = 'true', type = str)
	if date_end == '':
		params = {'from':fro, 'to':to, 'date_start':date_start}
	else:
		params = {'from':fro, 'to':to, 'date_start':date_start, 'date_end':date_end}
	r = requests.get('http://127.0.0.1:5000/apis/flight', params=params)
	r = r.json()['result']
	if (sort_by=='price'and asc=='true'):
		r = sorted(r, key = lambda i:i['zprice'], reverse=False)
	if (sort_by=='duration' and asc=='true'):
		r = sorted(r, key = lambda i:i['duration'], reverse=False)
	elif (sort_by=='price' and asc=='false'):
		r = sorted(r, key = lambda i:i['zprice'], reverse=True)
	elif (sort_by=='duration' and asc=='false'):
		r = sorted(r, key = lambda i:i['duration'], reverse=True)
	return jsonify({'result': r})


# params = {'from':'LHR', 'to':'ROM', 'date_start':'2019-01-30'}


    # print(res)

# service 3 hotel logic 1
@app.route('/apis/hotel_list', methods=['GET'])
def get_hotel_list():
	args = request.args.to_dict()
	lat = str(args['lat'])
	lng = str(args['lng'])
	inn = request.args.get('check_in', default = '', type = str)
	out = request.args.get('check_out', default = '', type = str)
	details = request.args.get('details', default = 'false', type = str)
	hotel = request.args.get('hotel', default = '', type = str)
	adults = args['adults']
	children = request.args.get('children', default = 0, type = int)
	rooms = args['rooms']
	chilren = '10,'*children
	price_range = request.args.get('price_range', default = '', type = str)
	params = {'lat':lat, 'lng':lng, 'check_in':inn, 'check_out':out, 'adults':adults, 'children':children, 'rooms':rooms, 'price_range':price_range}
	r = requests.get('http://127.0.0.1:5000/apis/hotel', params=params)
	r = r.json()['result']
	if details == 'true':
		resp_list = []
		for item in r:
			resp_dict = {}
			if item['name'] == hotel:
				return jsonify({'result': item})
	else:
		resp_list = []
		for item in r:
			resp_dict = {}
			resp_dict['name'] = item['name']
			query = 'https://maps.googleapis.com/maps/api/place/textsearch/json?query='+resp_dict['name']+' hotel&key=AIzaSyAb4xYI5EJJrkhkQ3LA_qpm_H0XWth4lgc'
			params2 = {'key':'key', 'query':query}
			r2 = requests.get(query)
			try:
				resp_dict['photo_ref'] = r2.json()['results'][0]['photos'][0]['photo_reference']
			except:
				resp_dict['photo_ref'] = "unavailable"
			try:
				resp_dict['rating'] = item['rating']
			except:
				resp_dict['photo_ref'] = "unavailable"
			try:
				resp_dict['price'] = item['price']
			except:
				resp_dict['photo_ref'] = "unavailable"
			try:
				resp_dict['type'] = item['type']
			except:
				resp_dict['photo_ref'] = "unavailable"
			resp_list.append(resp_dict)
			# except:
			# 	print('error')
	return jsonify({'result': resp_list})


# service 4 food logic 1
@app.route('/apis/food_options', methods=['GET'])
def get_food_options():
	# loc_dict = {}
	args = request.args.to_dict()
	check_list = []
	city = args['city']
	bars =args['bars']
	restaurants = args['restaurants']
	fast_foods =args['fast_foods']
	check_list.append(bars)
	check_list.append(restaurants)
	check_list.append(fast_foods)
	food_dict = {}
	for item in check_list:
		params = {'city':city, 'type':item}
		r = requests.get('http://127.0.0.1:5000/apis/food', params=params)
		r = r.json()['result']
		food_dict[item] = r
	return jsonify({'result': food_dict})


###################################################################################################
# adapter service layer

# service 1 places
@app.route('/apis/places', methods=['GET'])
def get_places():
    args = request.args.to_dict()
    city = args['city']
    params = {'key':'key', 'query':str(city)+'+point+of+interest'}
    r = requests.get('https://maps.googleapis.com/maps/api/place/textsearch/json', params=params)
    places_list = []
    for item in r.json()['results']:
        places_dict = {}
        places_dict['name'] = item['name']
        places_dict['rating'] = item['rating']
        places_dict['icon'] = item['icon']
        places_dict['formatted_address'] = item['formatted_address']
        places_dict['lat'] = item['geometry']['location']['lat']
        places_dict['lng'] = item['geometry']['location']['lng']
        try:
            places_dict['photo_ref'] = item['photos'][0]['photo_reference']
        except:
            places_dict['photo_ref'] = 'unavailable'
        places_list.append(places_dict)
    return jsonify({'result': places_list})

# service 2 place_detail
@app.route('/apis/place_detail',methods = ['GET'])
def get_place_details():
	loc_dict = {}
	args = request.args.to_dict()
	place = args['name']
	loc_dict['lat'] = str(args['lat'])
	loc_dict['lng'] = str(args['lng'])
	import wikipedia
	try:
		info = wikipedia.summary(place)
		loc_dict['info'] = info
	except:
		loc_dict['info'] = place+"'s text unavailable"
	loc_dict['place'] = place
	loc_dict['maps'] = "https://maps.googleapis.com/maps/api/js?key=key&callback=initMap"
	return jsonify({'result': loc_dict})

# service 3 flight
@app.route('/apis/flight', methods=['GET'])
def flight():
	from amadeus import Client, ResponseError
	import json
	args = request.args.to_dict()
	fromm = args['from']
	to = args['to']
	date_start = args['date_start']
	amadeus = Client(client_id='client_id', client_secret='secret')
	# try:
	if 'date_end' not in args:
		response = amadeus.shopping.flight_offers.get(origin=fromm, destination=to, departureDate=date_start)
		res =  response.data
	else:
		date_end = args['date_end']
		response = amadeus.shopping.flight_offers.get(origin=fromm, destination=to, departureDate=date_start, returnDate=date_end)
		res =  response.data
	resp_list = []
	for item in res:
		resp_dict = {}
		resp_dict['price'] = item['offerItems'][0]['price']['total']
		resp_dict['zprice'] = item['offerItems'][0]['price']['total'].zfill(8)
		resp_dict['travelClass'] =	item['offerItems'][0]['services'][0]['segments'][0]['pricingDetailPerAdult']['travelClass'].lower()
		if 'date_end' not in args:
			resp_dict['take_off'] = item['offerItems'][0]['services'][0]['segments'][0]['flightSegment']['departure']['at']
			resp_dict['take_off'] = str(dateutil.parser.parse(resp_dict['take_off']).time())
			resp_dict['arrival'] = item['offerItems'][0]['services'][0]['segments'][0]['flightSegment']['arrival']['at']
			resp_dict['arrival'] = str(dateutil.parser.parse(resp_dict['arrival']).time())
			resp_dict['duration'] = item['offerItems'][0]['services'][0]['segments'][0]['flightSegment']['duration']
			resp_dict['iata1'] = item['offerItems'][0]['services'][0]['segments'][0]['flightSegment']['departure']['iataCode']
			resp_dict['iata2'] = item['offerItems'][0]['services'][0]['segments'][0]['flightSegment']['arrival']['iataCode']
		else:
			resp_dict['take_off'] = item['offerItems'][0]['services'][0]['segments'][0]['flightSegment']['departure']['at']
			resp_dict['take_off'] = str(dateutil.parser.parse(resp_dict['take_off']).time())
			resp_dict['arrival'] = item['offerItems'][0]['services'][0]['segments'][0]['flightSegment']['arrival']['at']
			resp_dict['arrival'] = str(dateutil.parser.parse(resp_dict['arrival']).time())
			resp_dict['duration'] = item['offerItems'][0]['services'][0]['segments'][0]['flightSegment']['duration']
			resp_dict['iata1'] = item['offerItems'][0]['services'][0]['segments'][0]['flightSegment']['departure']['iataCode']
			resp_dict['iata2'] = item['offerItems'][0]['services'][0]['segments'][0]['flightSegment']['arrival']['iataCode']
			resp_dict['take_off2'] = item['offerItems'][0]['services'][1]['segments'][0]['flightSegment']['departure']['at']
			resp_dict['take_off2'] = str(dateutil.parser.parse(resp_dict['take_off2']).time())
			resp_dict['arrival2'] = item['offerItems'][0]['services'][1]['segments'][0]['flightSegment']['arrival']['at']
			resp_dict['arrival2'] = str(dateutil.parser.parse(resp_dict['arrival2']).time())
			resp_dict['duration2'] = item['offerItems'][0]['services'][1]['segments'][0]['flightSegment']['duration']
			resp_dict['r_iata1'] = item['offerItems'][0]['services'][1]['segments'][0]['flightSegment']['departure']['iataCode']
			resp_dict['r_iata2'] = item['offerItems'][0]['services'][1]['segments'][0]['flightSegment']['arrival']['iataCode']
			resp_dict['round_trip'] = "round trip"
		resp_dict['airlineCode'] = item['offerItems'][0]['services'][0]['segments'][0]['flightSegment']['carrierCode']
		resp_list.append(resp_dict)
	return jsonify({'result': resp_list})


# service 4 airline_link
@app.route('/apis/airline_link',methods = ['GET'])
def get_airline_link():
	from amadeus import Client, ResponseError
	import json
	args = request.args.to_dict()
	airlineCode = args['airlineCode']
	loc_dict = {}
	amadeus = Client(client_id='client_id', client_secret='secret')
	response =  amadeus.reference_data.urls.checkin_links.get(airlineCode=airlineCode)
	res =  response.data
	try:
		loc_dict['airline_link'] = res[0]['href']
	except:
		loc_dict['airline_link'] = 'link unavailable'
	return jsonify({'result': loc_dict})


# service 5 airline_name
@app.route('/apis/airline_name',methods = ['GET'])
def get_airline_name():
	from amadeus import Client, ResponseError
	import json
	args = request.args.to_dict()
	airlineCode = args['airlineCode']
	loc_dict = {}
	amadeus = Client(client_id='client_id', client_secret='secret')
	response =  amadeus.reference_data.airlines.get(airlineCodes=airlineCode)
	res =  response.data
	try:
		loc_dict['airline'] = res[0]['businessName']
	except:
		loc_dict['airline'] = 'name unavailable'
	return jsonify({'result': loc_dict})

# service 6 hotel
@app.route('/apis/hotel', methods=['GET'])
def hotel():
	from amadeus import Client, ResponseError
	import json
	args = request.args.to_dict()
	lat = str(args['lat'])
	lng = str(args['lng'])
	inn = request.args.get('check_in', default = '', type = str)
	out = request.args.get('check_out', default = '', type = str)
	adults = args['adults']
	children = request.args.get('children', default = '0', type = str)
	rooms = args['rooms']
	ratings = request.args.get('ratings', default = '', type = int)
	price_range = request.args.get('price_range', default = '', type = str)
	currency = request.args.get('currency', default = 'EUR', type = str)
	sort = request.args.get('sort', default = '', type = str)
	amadeus = Client(client_id='client_id', client_secret='secret')
	response = amadeus.shopping.hotel_offers.get(latitude=lat, longitude=lng, checkInDate=inn, checkOutDate= out, adults=adults,	chilAges=2, roomQuantity=rooms, ratings=ratings, priceRange=price_range, currency='EUR', sort=sort)
	res =  response.data
	resp_list = []
	for item in res:
		resp_dict = {}
		try:
			resp_dict['name'] = item['hotel']['name']
			resp_dict['rating'] = item['hotel']['rating']
			resp_dict['price'] = item['offers'][0]['price']['total']
			resp_dict['type'] = item['hotel']['type']
			resp_dict['address'] = item['hotel']['address']['lines']
			resp_dict['amenities'] = item['hotel']['amenities']
			resp_dict['contact'] = item['hotel']['contact']
			resp_dict['lng'] = item['hotel']['longitude']
			resp_dict['lat'] = item['hotel']['latitude']
			resp_dict['description'] = item['offers'][0]['room']['description']
			resp_list.append(resp_dict)
		except:
			print('error')
	return jsonify({'result': resp_list})


# service 7 places
@app.route('/apis/geocoding', methods=['GET'])
def get_geocoding():
	args = request.args.to_dict()
	city = args['city']
	params = {'key':'key', 'address':city}
	r = requests.get('https://maps.googleapis.com/maps/api/geocode/json', params=params)
	r = r.json()['results'][0]['geometry']['location']
	return jsonify({'result': r})



# service 8 food
@app.route('/apis/food', methods=['GET'])
def get_food():
	args = request.args.to_dict()
	city = args['city']
	typpe = args['type']
	query = city+'+'+typpe
	params = {'key':'key', 'query':query}
	r = requests.get('https://maps.googleapis.com/maps/api/place/textsearch/json', params = params)
	food_list = []
	for ress in r.json()['results']:
		food_dict2 = {}
		food_dict2['name'] = ress['name']
		food_dict2['rating'] = ress['rating']
		food_dict2['formatted_address'] = ress['formatted_address']
		food_dict2['lat'] = ress['geometry']['location']['lat']
		food_dict2['lng'] = ress['geometry']['location']['lng']
		try:
			food_dict2['photo_ref'] = ress['photos'][0]['photo_reference']
		except:
			food_dict2['photo_ref'] = 'unavailable'
		try:
			food_dict2['price'] = ress['price_level']
		except:
			food_dict2['price'] = 'unavailable'
		food_list.append(food_dict2)
	return jsonify({'result': food_list})



########################## data layer #################################
class Users(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True,autoincrement = True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)


    def __repr__(self):
        return '<User %r>' % self.email

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a valid email address.')


class RegistrationForm(FlaskForm):
    firstname = StringField('Firstname', validators=[DataRequired()])
    lastname = StringField('Lastname', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('GetStarted')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class Usergoogle(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True,autoincrement = True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

    def __init__(self, email, name):
        self.name = name
        self.email = email

    def __repr__(self):
        return '<User %r>' % self.email

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated


class FOODS(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	place = db.Column(db.Text)
	rating = db.Column(db.Text)
	address = db.Column(db.Text)
	price = db.Column(db.Text)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	user_gid = db.Column(db.Integer, db.ForeignKey('usergoogle.id'))


	if user_id == True:
		def __init__(self, place, rating, address, price, user_id):
			self.place = place
			self.rating = rating
			self.address = address
			self.user_id = user_id
	if user_gid == True:
		def __init__(self, place, rating, address, price, user_gid):
			self.place = place
			self.rating = rating
			self.address = address
			self.price = price
			self.user_gid = user_gid

	def __repr__(self):
		return '<Task %r>' % self.content

class POIS(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	place = db.Column(db.Text)
	rating = db.Column(db.Text)
	address = db.Column(db.Text)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	user_gid = db.Column(db.Integer, db.ForeignKey('usergoogle.id'))


	if user_id == True:
		def __init__(self, place, rating, address, user_id):
			self.place = place
			self.rating = rating
			self.address = address
			self.user_id = user_id

	if user_gid == True:
		def __init__(self, place, rating, address, user_gid):
			self.place = place
			self.rating = rating
			self.address = address
			self.user_gid = user_gid

	def __repr__(self):
		return self.place

db.create_all()
# run program
if __name__ == '__main__':
    app.run(debug=True)
