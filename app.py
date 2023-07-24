from flask import Flask,request,render_template,jsonify
from src.phishingdetection.pipeline.predict import PredictionPipeline



app=Flask(__name__)



@app.route('/home')
def home_page():
    return render_template('index.html')


@app.route('/check_phishing',methods=['GET','POST'])

def phishing_check():
    if request.method=='GET':
        return render_template('index.html')
    
    else:
        
        
        url = request.form.get('url_input')

        pred_obj = PredictionPipeline(url)


        isphishing = pred_obj.predict()
        print(isphishing)
        result = ''
        if isphishing == 0:
            result = 'The website is safe to use'
        else:
            result = 'The website may be harmful'


       
        
        return render_template('index.html',result = result, url = url)


if __name__=="__main__":
    app.run(host='0.0.0.0')