import os
from dotenv import load_dotenv
import pandas as pd
import plotly.express as px
import plotly.io as pio
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import statsmodels.api as sm
from statsmodels.stats.diagnostic import het_breuschpagan, acorr_breusch_godfrey
from statsmodels.stats.stattools import durbin_watson
from statsmodels.tsa.stattools import adfuller
from statsmodels.tsa.arima.model import ARIMA
import plotly.graph_objects as go


load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise ValueError("No SECRET_KEY set for Flask application. Check your .env file.")  # Change this before deploying!

# Configure the SQLite Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

UPLOAD_FOLDER = 'instance/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True) # Creates the folder if it doesn't exist
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Define the User Architecture
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


# Generate the Database Tables
with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/sw.js')
def serve_sw():
    return send_from_directory('static', 'sw.js')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # You must pull the real user object from the database for the hash checks to work
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        action = request.form.get('action')

        # Action 1: Security Override (Change Password)
        if action == 'change_password':
            old_pass = request.form.get('old_password')
            new_pass = request.form.get('new_password')

            # --- REAL DATABASE LOGIC ---
            if check_password_hash(user.password, old_pass):
                user.password = generate_password_hash(new_pass)
                db.session.commit()
                flash('SYSTEM: SECURITY CREDENTIALS UPDATED.', 'success')
            else:
                flash('SYS.ERR: OLD CREDENTIALS INVALID.', 'error')

            return redirect(url_for('profile'))

        # Action 2: Total Wipe (Delete Account)
        elif action == 'delete_account':
            auth_pass = request.form.get('delete_password')

            # --- REAL DATABASE LOGIC ---
            if check_password_hash(user.password, auth_pass):
                db.session.delete(user)
                db.session.commit()
                session.clear()
                flash('SYSTEM: USER DATA PURGED FROM MAINFRAME.', 'success')
                return redirect(url_for('index'))
            else:
                flash('SYS.ERR: INVALID AUTHORIZATION. WIPE ABORTED.', 'error')
                return redirect(url_for('profile'))

    # THIS MUST BE OUTSIDE THE POST BLOCK
    # This handles the initial GET request to actually render the page.
    return render_template('profile.html', user=user)


# --- SYSTEM LOGIN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Search the database for the user
        user = User.query.filter_by(username=username).first()

        # Verify user exists AND the passkey matches the hash
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('tools'))  # Route them to the main app
        else:
            flash('ACCESS DENIED: Invalid ID or Passkey','error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))



# --- INITIALIZE PROFILE (REGISTER) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validation checks
        if password != confirm_password:
            flash('ERROR: Passkeys do not match.','error')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('ERROR: User ID already active.','error')
            return redirect(url_for('register'))

        # Encrypt the passkey and save to database
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('SYSTEM: Profile Generated. Please Authenticate.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# --- SECURE TOOLS MODULE (Placeholder) ---
@app.route('/tools')
def tools():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # This tells Flask to load your Nothing-themed dashboard instead of the raw text
    return render_template('tools.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('dataset')

        if not file or file.filename == '':
            flash('ERROR: NO FILE DETECTED.')
            return redirect(request.url)

        try:
            # Parse the data
            if file.filename.endswith('.csv'):
                df = pd.read_csv(file)
            elif file.filename.endswith('.xlsx') or file.filename.endswith('.xls'):
                df = pd.read_excel(file)
            else:
                flash('ERROR: UNSUPPORTED FORMAT.')
                return redirect(request.url)

            # --- THE NEW MEMORY PROTOCOL ---
            # 1. Save the dataframe to a standardized internal file
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{session['user_id']}_active.csv")
            df.to_csv(save_path, index=False)

            # 2. Store the file path and columns in the user's session
            session['active_data_path'] = save_path
            columns = list(df.columns)
            session['active_columns'] = columns
            # -------------------------------

            rows, cols = df.shape

            return render_template('upload.html',
                                   status="DATA INJECTED SUCCESSFULLY",
                                   rows=rows,
                                   cols=cols,
                                   columns=columns,
                                   filename=file.filename)

        except Exception as e:
            flash(f'CRITICAL ERROR: {str(e)}')
            return redirect(request.url)

    return render_template('upload.html')


@app.route('/ols', methods=['GET', 'POST'])
def ols():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Load active columns for the GET request UI
    columns = session.get('active_columns', [])

    if request.method == 'POST':
        y_var = request.form.get('y_var')
        x_vars = request.form.getlist('x_vars')  # getlist() catches multiple checkboxes

        # Failsafe: Ensure they selected variables
        if not y_var or not x_vars:
            flash('ERROR: MUST SELECT ONE TARGET AND AT LEAST ONE PREDICTOR.')
            return redirect(url_for('ols'))

        try:
            # 1. Load the active dataset from memory
            data_path = session.get('active_data_path')
            df = pd.read_csv(data_path)

            # 2. Clean the data (Drop rows with missing values in selected columns)
            model_data = df[[y_var] + x_vars].dropna()

            # 3. Define the Math
            Y = model_data[y_var]
            X = model_data[x_vars]

            # Add the Y-intercept (constant) to the equation. Crucial for standard OLS!
            X = sm.add_constant(X)

            # 4. Execute the Regression
            model = sm.OLS(Y, X).fit()

            # 5. Extract the Results into a clean dictionary
            results = {
                'dependent': y_var,
                'observations': int(model.nobs),
                'r_squared': round(model.rsquared, 4),
                'adj_r_squared': round(model.rsquared_adj, 4),
                'f_stat_p': round(model.f_pvalue, 4),
                # Convert series to dictionaries for easy looping in HTML
                'coefficients': round(model.params, 4).to_dict(),
                'p_values': round(model.pvalues, 4).to_dict(),
                'std_errors': round(model.bse, 4).to_dict()
            }

            return render_template('ols.html', columns=columns, results=results)

        except Exception as e:
            flash(f'CALCULATION ERROR: Ensure selected variables are numeric. Details: {str(e)}')
            return redirect(url_for('ols'))

    return render_template('ols.html', columns=columns)


# Add this new route near your /load_vault route
@app.route('/vault')
def vault():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Path to your vault folder
    vault_dir = os.path.join('static', 'vault')

    # Python scans the folder and finds all CSV and Excel files
    try:
        datasets = [f for f in os.listdir(vault_dir) if f.endswith(('.csv', '.xlsx', '.xls'))]
    except FileNotFoundError:
        datasets = []  # Failsafe if the folder doesn't exist yet

    # Send the list of files to the new vault template
    return render_template('vault.html', datasets=datasets)

@app.route('/load_vault/<dataset_name>')
def load_vault(dataset_name):
    # Security Check
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        # 1. Locate the file in your static/vault directory
        vault_path = os.path.join('static', 'vault', dataset_name)

        # 2. Read the pre-loaded data
        if dataset_name.endswith('.csv'):
            df = pd.read_csv(vault_path)
        else:
            df = pd.read_excel(vault_path)

        # 3. Save it to the user's active memory (mimicking the upload process)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{session['user_id']}_active.csv")
        df.to_csv(save_path, index=False)

        # 4. Update the session variables so the OLS engine knows what to look for
        session['active_data_path'] = save_path
        session['active_columns'] = list(df.columns)

        # Flash a system message and send them directly to the math engine
        flash(f'SYSTEM OVERRIDE: {dataset_name.upper()} LOADED FROM VAULT.')
        return redirect(url_for('ols'))

    except FileNotFoundError:
        flash(f'ERROR: DATASET [{dataset_name}] CORRUPTED OR MISSING FROM VAULT.')
        return redirect(url_for('tools'))
    except Exception as e:
        flash(f'CRITICAL ERROR: {str(e)}')
        return redirect(url_for('tools'))


@app.route('/visual', methods=['GET', 'POST'])
def visual():
    # Security Check
    if 'user_id' not in session:
        return redirect(url_for('login'))

    columns = session.get('active_columns', [])

    # If no data in memory, kick them back to tools
    if not columns:
        flash('ERROR: NO DATA DETECTED IN ACTIVE MEMORY.', 'error')
        return redirect(url_for('tools'))

    plot_html = None
    selected_x = None
    selected_y = None

    if request.method == 'POST':
        selected_y = request.form.get('y_var')
        selected_x = request.form.get('x_var')

        if not selected_y or not selected_x:
            flash('ERROR: MUST SELECT BOTH X AND Y AXES.', 'error')
            return redirect(url_for('visual'))

        try:
            # Load the data
            data_path = session.get('active_data_path')
            df = pd.read_csv(data_path)

            # Drop missing values for these specific columns
            df_clean = df[[selected_x, selected_y]].dropna()

            # Generate the Interactive Plot
            # Using statsmodels OLS for the trendline
            fig = px.scatter(
                df_clean,
                x=selected_x,
                y=selected_y,
                trendline="ols",
                title=f"{selected_y} vs {selected_x}"
            )

            # ----- THE REGRESSIONARY HARDWARE THEME -----
            fig.update_traces(
                marker=dict(color='#00ff41', size=6, opacity=0.7),  # Matrix Green Dots
                line=dict(color='#E50914', width=3)  # Nothing Red Trendline
            )

            fig.update_layout(
                paper_bgcolor='black',  # Background surrounding plot
                plot_bgcolor='#0a0a0a',  # Background of the plot itself
                font=dict(family="Courier New, monospace", color="#9ca3af", size=12),
                title=dict(font=dict(color="white", size=18)),
                xaxis=dict(showgrid=True, gridwidth=1, gridcolor='#1A1A1A', zerolinecolor='#333333'),
                yaxis=dict(showgrid=True, gridwidth=1, gridcolor='#1A1A1A', zerolinecolor='#333333'),
                margin=dict(l=40, r=40, t=60, b=40)
            )
            # --------------------------------------------

            # Convert the interactive plot to HTML to inject into the template
            plot_html = pio.to_html(fig, full_html=False, config={'displayModeBar': False})

        except Exception as e:
            flash(f'RENDER ERROR: Could not map visual vector. {str(e)}', 'error')
            return redirect(url_for('visual'))

    return render_template('visual.html', columns=columns, plot_html=plot_html, current_x=selected_x,
                           current_y=selected_y)


# Update your existing /protocol route to look like this:
@app.route('/protocol')
def protocol():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    columns = session.get('active_columns', [])
    if not columns:
        flash('SYSTEM ERROR: INITIALIZE DATA BEFORE STARTING PROTOCOL.', 'error')
        return redirect(url_for('tools'))

    # Gatekeeper Variables (Handles Stages 1 & 2 automatically)
    stage = session.get('protocol_stage', 1)
    diagnostics = session.get('protocol_diagnostics', {})

    # Matrix Variables (Initialize empty so the template doesn't crash)
    results = None
    fit_metrics = None
    plot_html = None

    # --- STAGE 3 & 4 LOGIC (INFERENCE & EVALUATION) ---
    if stage >= 3:
        try:
            # Re-load data and run OLS
            data_path = session.get('active_data_path')
            y_var = session.get('protocol_y')
            x_vars = session.get('protocol_x')

            df = pd.read_csv(data_path)
            df_clean = df[[y_var] + x_vars].dropna()

            Y = df_clean[y_var]
            X = sm.add_constant(df_clean[x_vars])
            model = sm.OLS(Y, X).fit()

            # STAGE 03: Inference Table Packaging
            results = []
            for var in model.params.index:
                p_val = model.pvalues[var]
                # Academic Star System
                stars = "***" if p_val < 0.01 else "**" if p_val < 0.05 else "*" if p_val < 0.1 else ""

                results.append({
                    'variable': 'Constant (Intercept)' if var == 'const' else var,
                    'coef': round(model.params[var], 4),
                    'std_err': round(model.bse[var], 4),
                    't_stat': round(model.tvalues[var], 4),
                    'p_value': round(p_val, 4),
                    'stars': stars,
                    'is_significant': p_val < 0.05  # Highlight row if significant at 5%
                })

            # STAGE 04: Evaluation Metrics & Plotly Render
            if stage == 4:
                # 1. Goodness of Fit Metrics
                fit_metrics = {
                    'r_squared': round(model.rsquared, 4),
                    'adj_r_squared': round(model.rsquared_adj, 4),
                    'f_stat': round(model.fvalue, 4),
                    'f_pvalue': round(model.f_pvalue, 6)
                }

                # 2. Visual Matrix (Actual vs Predicted)
                import plotly.express as px
                import plotly.io as pio

                Y_pred = model.predict(X)
                plot_df = pd.DataFrame({'Actual': Y, 'Predicted': Y_pred})

                fig = px.scatter(
                    plot_df, x='Actual', y='Predicted',
                    trendline="ols",
                    title="Model Fit: Actual vs Predicted Values"
                )

                # The Regressionary Hardware Theme
                fig.update_traces(
                    marker=dict(color='#00ff41', size=6, opacity=0.7),
                    line=dict(color='#E50914', width=3)
                )
                fig.update_layout(
                    paper_bgcolor='black', plot_bgcolor='#0a0a0a',
                    font=dict(family="Courier New, monospace", color="#9ca3af", size=12),
                    title=dict(font=dict(color="white", size=18)),
                    xaxis=dict(title=f"Actual {y_var}", showgrid=True, gridwidth=1, gridcolor='#1A1A1A', zerolinecolor='#333333'),
                    yaxis=dict(title=f"Predicted {y_var}", showgrid=True, gridwidth=1, gridcolor='#1A1A1A', zerolinecolor='#333333'),
                    margin=dict(l=40, r=40, t=60, b=40)
                )

                plot_html = pio.to_html(fig, full_html=False, config={'displayModeBar': False})

        except Exception as e:
            flash(f'RENDER ERROR: INFERENCE/EVALUATION FAILURE. {str(e)}', 'error')
            session['protocol_stage'] = 1  # Reset protocol if math breaks
            return redirect(url_for('protocol'))
    # --------------------------

    # Pass everything to the HTML Template
    return render_template(
        'protocol.html',
        columns=columns,
        stage=stage,
        diagnostics=diagnostics,
        results=results,
        fit_metrics=fit_metrics,
        plot_html=plot_html
    )

@app.route('/protocol_step_1', methods=['POST'])
def protocol_step_1():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    y_var = request.form.get('y_var')
    x_vars = request.form.getlist('x_vars')

    if not y_var or not x_vars:
        flash('SYS.ERR: MUST SELECT TARGET (Y) AND AT LEAST ONE PREDICTOR (X).', 'error')
        return redirect(url_for('protocol'))

    try:
        # 1. Load and clean the active matrix
        data_path = session.get('active_data_path')
        df = pd.read_csv(data_path)
        df_clean = df[[y_var] + x_vars].dropna()

        Y = df_clean[y_var]
        X = sm.add_constant(df_clean[x_vars])

        # 2. Fit the temporary OLS Model
        model = sm.OLS(Y, X).fit()

        # 3. RUN DIAGNOSTICS (The Health Check)

        # Heteroskedasticity (Breusch-Pagan Test)
        # Returns [lm_stat, p-value, f-value, f_p-value]
        bp_test = het_breuschpagan(model.resid, model.model.exog)
        bp_pval = bp_test[1]
        bp_status = "NOMINAL" if bp_pval > 0.05 else "CRITICAL"

        # Autocorrelation (Breusch-Godfrey Test)
        bg_test = acorr_breusch_godfrey(model, nlags=1)
        bg_pval = bg_test[1]
        bg_status = "NOMINAL" if bg_pval > 0.05 else "CRITICAL"

        # Autocorrelation (Durbin-Watson Stat)
        dw_stat = durbin_watson(model.resid)
        dw_status = "NOMINAL" if 1.5 < dw_stat < 2.5 else "CRITICAL"

        # 4. Save results to Session Memory
        session['protocol_y'] = y_var
        session['protocol_x'] = x_vars
        session['protocol_diagnostics'] = {
            'hetero': {'p': round(bp_pval, 4), 'status': bp_status},
            'auto_bg': {'p': round(bg_pval, 4), 'status': bg_status},
            'auto_dw': {'stat': round(dw_stat, 2), 'status': dw_status}
        }

        # Advance the State Machine to Gate 02
        session['protocol_stage'] = 2
        flash('SYSTEM: EQUATION INITIALIZED. DIAGNOSTICS READY.', 'success')
        return redirect(url_for('protocol'))

    except Exception as e:
        flash(f'RENDER ERROR: MATRIX FAILURE. {str(e)}', 'error')
        return redirect(url_for('protocol'))


@app.route('/protocol_step_2', methods=['POST'])
def protocol_step_2():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Advance the State Machine to Gate 03
    session['protocol_stage'] = 3
    flash('SYSTEM: DIAGNOSTICS LOGGED. INFERENCE MATRIX ONLINE.', 'success')
    return redirect(url_for('protocol'))


@app.route('/protocol_step_3', methods=['POST'])
def protocol_step_3():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Advance to the Final Evaluation Stage
    session['protocol_stage'] = 4
    flash('SYSTEM: INFERENCE COMPLETE. RENDERING EVALUATION MATRIX.', 'success')
    return redirect(url_for('protocol'))

@app.route('/protocol_reset', methods=['POST'])
def protocol_reset():
    session['protocol_stage'] = 1
    session.pop('protocol_diagnostics', None)
    session.pop('protocol_y', None)
    session.pop('protocol_x', None)
    return redirect(url_for('tools'))


@app.route('/timeseries', methods=['GET', 'POST'])
def timeseries():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    columns = session.get('active_columns', [])
    if not columns:
        flash('SYSTEM ERROR: INITIALIZE DATA BEFORE ENGAGING TEMPORAL MATRIX.', 'error')
        return redirect(url_for('tools'))

    diagnostics = None
    plot_html = None

    if request.method == 'POST':
        date_col = request.form.get('date_col')
        target_col = request.form.get('target_col')
        steps = int(request.form.get('steps', 10))

        if not date_col or not target_col:
            flash('SYS.ERR: MUST SELECT TIME INDEX AND TARGET VECTOR.', 'error')
            return redirect(url_for('timeseries'))

        try:
            # 1. Load and Prepare Time Series Data
            df = pd.read_csv(session.get('active_data_path'))
            df = df.dropna(subset=[date_col, target_col])

            # Sort by date (crucial for time series)
            df[date_col] = pd.to_datetime(df[date_col], errors='coerce')
            df = df.dropna(subset=[date_col]).sort_values(by=date_col)

            Y = df[target_col].values
            dates = df[date_col].dt.strftime('%Y-%m-%d').tolist()

            # 2. Stationarity Check (Augmented Dickey-Fuller)
            adf_result = adfuller(Y)
            p_value = round(adf_result[1], 4)
            is_stationary = p_value < 0.05

            # 3. Fit ARIMA Model (Using a basic 1,1,1 order for robustness on dummy data)
            model = ARIMA(Y, order=(1, 1, 1))
            fitted_model = model.fit()

            # 4. Forecast Future Steps
            forecast = fitted_model.forecast(steps=steps)

            # Generate future dummy dates for the plot
            last_date = pd.to_datetime(dates[-1])
            future_dates = [(last_date + pd.Timedelta(days=i)).strftime('%Y-%m-%d') for i in range(1, steps + 1)]

            # 5. Render the Hologram (Plotly)
            fig = go.Figure()

            # Historical Data Line
            fig.add_trace(
                go.Scatter(x=dates, y=Y, mode='lines+markers', name='Historical', line=dict(color='#00ff41', width=2),
                           marker=dict(size=4)))

            # Forecasted Data Line (Red and dashed)
            fig.add_trace(go.Scatter(x=future_dates, y=forecast, mode='lines+markers', name='Forecast',
                                     line=dict(color='#E50914', width=2, dash='dot'), marker=dict(size=6)))

            fig.update_layout(
                paper_bgcolor='black', plot_bgcolor='#0a0a0a',
                font=dict(family="Courier New, monospace", color="#9ca3af", size=12),
                title=dict(text=f"ARIMA Forecast: {target_col}", font=dict(color="white", size=18)),
                xaxis=dict(showgrid=True, gridwidth=1, gridcolor='#1A1A1A'),
                yaxis=dict(showgrid=True, gridwidth=1, gridcolor='#1A1A1A'),
                margin=dict(l=40, r=40, t=60, b=40),
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
            )
            plot_html = pio.to_html(fig, full_html=False, config={'displayModeBar': False})

            diagnostics = {
                'adf_p': p_value,
                'stationary': is_stationary,
                'target': target_col
            }
            flash('SYSTEM: FORECAST RENDERED SUCCESSFULLY.', 'success')

        except Exception as e:
            flash(f'RENDER ERROR: TEMPORAL MATRIX FAILURE. {str(e)}', 'error')
            return redirect(url_for('timeseries'))

    return render_template('timeseries.html', columns=columns, diagnostics=diagnostics, plot_html=plot_html)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')