#need change based on your env
PYTHON_VERSION=$(python3 --version)
VENV="ta-lib-venv"
sudo apt-get install python3-tk"$PYTHON_VERSION"-dev libatlas-base-dev -y
python3 -m venv "$VENV"
source "$VENV/bin/activate"
pip3 install -r src/requirements.txt