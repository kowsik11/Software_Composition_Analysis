import subprocess
import sys

def install_requirements(requirements_file):
    try:
        with open(requirements_file) as f:
            packages = f.readlines()
        for package in packages:
            package = package.strip()
            if package:
                print(f'Installing {package}...')
                try:
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
                    print(f'{package} installed successfully.')
                except subprocess.CalledProcessError:
                    print(f'Failed to install {package}, trying latest version...')
                    try:
                        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', package])
                        print(f'Latest version of {package} installed.')
                    except subprocess.CalledProcessError as e:
                        print(f'Failed to install the latest version of {package}. Error: {e}')
            else:
                print('Empty line found in requirements file, skipping.')
    except Exception as e:
        print(f'An error occurred: {e}')

# Example usage
install_requirements('requirements.txt')