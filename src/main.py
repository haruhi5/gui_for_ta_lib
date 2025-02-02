import sys
import os
import pandas as pd
import matplotlib.pyplot as plt
import requests
from io import StringIO
import tkinter as tk
from tkinter import ttk, messagebox
import numpy as np
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import openai

try:
    import talib
    TALIB_AVAILABLE = True
except ModuleNotFoundError:
    print("Warning: TA-Lib is not installed. Some features may not work.")
    TALIB_AVAILABLE = False

def encrypt_key(key, filename="api_key.enc", password="your_strong_password"):
    key_bytes = key.encode()
    password_bytes = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(password_bytes, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(key_bytes, AES.block_size))
    with open(filename, "wb") as f:
        f.write(cipher.iv + ciphertext)

def decrypt_key(filename="api_key.enc", password="your_strong_password"):
    password_bytes = hashlib.sha256(password.encode()).digest()
    with open(filename, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(password_bytes, AES.MODE_CBC, iv)
    decrypted_key = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
    return decrypted_key

API_KEY_FILE = "api_key.enc"
# Set your OpenAI API Key
OPENAI_API_KEY = "your_openai_api_key"

if os.path.exists(API_KEY_FILE):
    ALPHA_VANTAGE_API_KEY = decrypt_key(API_KEY_FILE)
else:
    ALPHA_VANTAGE_API_KEY = input("Enter your Alpha Vantage API Key: ")
    encrypt_key(ALPHA_VANTAGE_API_KEY, API_KEY_FILE)

AVAILABLE_STOCKS = ["AAPL", "GOOGL", "MSFT", "AMZN", "TSLA"]  # Sample stock list

TIME_RANGE_OPTIONS = {
    "1 Day": 1,
    "5 Days": 5,
    "1 Week": 7,
    "1 Month": 30,
    "6 Months": 180,
    "1 Year": 365,
    "5 Years": 1825,
    "10 Years": 18250
}

# add ta-lib api here
INDICATOR_DESCRIPTIONS = {
    "SMA": "Simple Moving Average - Averages price over a set period.",
    "EMA": "Exponential Moving Average - A weighted moving average giving more importance to recent prices.",
    "RSI": "Relative Strength Index - Measures momentum of stock prices.",
    "MACD": "Moving Average Convergence Divergence - Used to identify trends and reversals.",
    "BBANDS": "Bollinger Bands - Measures volatility using standard deviations above and below a moving average.",
    "HT_TRENDLINE": "Hilbert Transform Trendline - A cycle indicator.",
    "ATR": "Average True Range - A volatility indicator.",
    "HT_SINE": "Hilbert Transform Sine Wave - Identifies market cycles.",
    "HT_PHASOR": "Hilbert Transform Phasor Components - Identifies phase components of cycles.",
    "HT_TRENDMODE": "Hilbert Transform - Trend vs Cycle Mode",
    "TSF": "Time Series Forecast - Forecasts the next value in a time series."
}

class TaLibGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("TA-Lib Stock Analysis")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Stock Symbol Selection
        self.symbol_label = ttk.Label(root, text="Select Stock Symbol:")
        self.symbol_label.grid(row=0, column=0, padx=10, pady=5)
        
        self.symbol_var = tk.StringVar()
        self.symbol_menu = ttk.Combobox(root, textvariable=self.symbol_var, values=AVAILABLE_STOCKS)
        self.symbol_menu.grid(row=0, column=1, padx=10, pady=5)

        self.use_stored_var = tk.BooleanVar()
        self.use_stored_check = ttk.Checkbutton(root, text="Use Stored Data", variable=self.use_stored_var)
        self.use_stored_check.grid(row=0, column=2, padx=10, pady=5)
        
        self.fetch_button = ttk.Button(root, text="Fetch Data", command=self.fetch_stock_data)
        self.fetch_button.grid(row=0, column=3, padx=10, pady=5)
        
        # Time Range Selection
        self.range_label = ttk.Label(root, text="Select Time Range:")
        self.range_label.grid(row=1, column=0, padx=10, pady=5)
        
        self.range_var = tk.StringVar()
        self.range_menu = ttk.Combobox(root, textvariable=self.range_var, values=list(TIME_RANGE_OPTIONS.keys()))
        self.range_menu.grid(row=1, column=1, padx=10, pady=5)
        self.range_menu.current(5)  # Default to 6 months
        
        # Indicator Selection
        self.indicator_label = ttk.Label(root, text="Select Indicator:")
        self.indicator_label.grid(row=2, column=0, padx=10, pady=5)
        
        self.indicator_var = tk.StringVar()
        self.indicator_menu = ttk.Combobox(root, textvariable=self.indicator_var)
        self.indicator_menu.grid(row=2, column=1, padx=10, pady=5)
        
        self.description_label = ttk.Label(root, text="")
        self.description_label.grid(row=3, column=0, columnspan=3, padx=10, pady=5)
        
        self.indicator_menu.bind("<<ComboboxSelected>>", self.show_indicator_description)
        
        self.compute_button = ttk.Button(root, text="Compute Indicator", command=self.compute_indicator)
        self.compute_button.grid(row=2, column=2, padx=10, pady=5)
        
        self.analysis_label = tk.Label(root, text="Analysis will appear here", wraplength=600, justify="left")
        self.analysis_label.grid(row=2, column=3, columnspan=4, padx=10, pady=5)
        
        self.stock_data = None
        self.fig, self.ax = None, None
        self.vlines = []
        self.data_file = os.path.join(os.path.dirname(__file__), "../data/fetched_data.csv")
        print(self.data_file)
        self.populate_indicators()
    
    def fetch_stock_data(self):
        if self.use_stored_var.get() and os.path.exists(self.data_file):
            self.stock_data = pd.read_csv(self.data_file, parse_dates=["timestamp"], index_col="timestamp")
            messagebox.showinfo("Success", "Loaded stored data successfully.")
            return

        symbol = self.symbol_var.get().strip().upper()
        if not symbol:
            messagebox.showerror("Error", "Please select a stock symbol.")
            return

        try:
            url = f"https://www.alphavantage.co/query?function=TIME_SERIES_DAILY&symbol={symbol}&apikey={ALPHA_VANTAGE_API_KEY}&outputsize=full&datatype=csv"
            response = requests.get(url)
            response.raise_for_status()
            self.stock_data = pd.read_csv(StringIO(response.text), parse_dates=["timestamp"], index_col="timestamp")
            self.stock_data.to_csv(self.data_file)  # Store fetched data
            messagebox.showinfo("Success", f"Successfully fetched and stored data for {symbol}")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to fetch data: {e}")
    
    def populate_indicators(self):
        self.indicator_menu["values"] = sorted(INDICATOR_DESCRIPTIONS.keys())
    
    def show_indicator_description(self, event):
        indicator = self.indicator_var.get()
        description = INDICATOR_DESCRIPTIONS.get(indicator, "No description available.")
        self.description_label.config(text=description)
    
    def compute_indicator(self):
        if self.stock_data is None:
            messagebox.showerror("Error", "Please fetch stock data first.")
            return

        indicator = self.indicator_var.get()
        if not indicator:
            messagebox.showerror("Error", "Please select an indicator.")
            return

        selected_range = TIME_RANGE_OPTIONS[self.range_var.get()]
        filtered_data = self.stock_data if selected_range is None else self.stock_data.tail(selected_range)

        try:
            close_prices = filtered_data["close"].dropna()

            # Convert NumPy array to Pandas Series for plotting
            plot_tags = {
                "Close Price": filtered_data["close"].dropna(),
                indicator: pd.Series(getattr(talib, indicator)(close_prices), index=close_prices.index),
                "Beta Coefficient": pd.Series(talib.BETA(filtered_data["high"], filtered_data["low"], timeperiod=5), index=close_prices.index),
                "Correlation": pd.Series(talib.CORREL(filtered_data["high"], filtered_data["low"], timeperiod=5), index=close_prices.index),
                "Standard Deviation":pd.Series(talib.STDDEV(close_prices, timeperiod=5), index=close_prices.index),
                "Variance":pd.Series(talib.VAR(close_prices, timeperiod=5), index=close_prices.index),
            }

            # if indicator == "TSF":
            #     forecast_dates = [close_prices.index[-1] + pd.Timedelta(days=i) for i in range(1, 100)]
            #     forecast_values = #TODO

            self.fig, self.ax = plt.subplots(3, 2, figsize=(10, 12))

            for (title, data), ax in zip(plot_tags.items(), self.ax.flatten()):
                ax.plot(data.index, data, label=title, color=np.random.rand(3,))
                ax.set_title(title)
                ax.legend()
                ax.grid(True)
                # if title == "TSF":
                #     ax.plot(forecast_dates, forecast_values, label="100-day Forecast", linestyle='dashed', color='green')

            plt.tight_layout()
            self.fig.canvas.mpl_connect('motion_notify_event', self.on_mouse_move)
            plt.savefig("plot.png")
            plt.show()
            self.analyze_plot()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_mouse_move(self, event):
        if event.inaxes is None:
            return
        
        for vline in self.vlines:
            vline.remove()
        
        self.vlines = [ax.axvline(event.xdata, color='red', linestyle='dashed') for ax in self.ax.flatten()]
        event.canvas.draw()

    def analyze_plot(self):
        messagebox.showinfo("Analysis", "The plot has been saved as 'plot.png'. You can now send it to ChatGPT for analysis.")

    # def analyze_plot(self):
    #     try:
    #         with open("plot.png", "rb") as image_file:
    #             encoded_image = image_file.read()
            
    #         response = openai.ChatCompletion.create(
    #             model="gpt-4-vision-preview",
    #             messages=[
    #                 {"role": "system", "content": "You are a financial analyst. Analyze the stock trend based on the given plot."},
    #                 {"role": "user", "content": encoded_image}
    #             ]
    #         )
            
    #         analysis = response["choices"][0]["message"]["content"]
    #         self.analysis_label.config(text=analysis)
    #     except Exception as e:
    #         messagebox.showerror("Error", f"Failed to analyze plot: {e}")

    def on_close(self):
        self.root.destroy()
        sys.exit()

if __name__ == "__main__":
    root = tk.Tk()
    app = TaLibGUI(root)
    root.mainloop()
    exit
