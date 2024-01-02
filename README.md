This is Dip project and in this project we are basically performing video stegangrapy

# Video Steganography

## Usage

### Prerequisites

Make sure you have Python installed on your system. If not, you can download it from [here](https://www.python.org/).

### Installation

Install the required Python packages using the following command:

``` 
pip install opencv-python pycryptodome pillow 

``` 

### Running Code

``` 
 python tk.py 
``` 


# Running the Application


### Encoding Data into a Video

    Select Encoding Mode:
       Click on the "Encode" tab in the GUI.

    Choose Video and Data Files:
     Click on the "Choose Video" button to select the video file that will act as the carrier.
     Click on the "Choose Data" button to select the file that you want to hide within the video.

    Provide Encryption Key and Initialization Vector (IV):
        Enter a secure encryption key and an initialization vector in the respective fields.

    Initiate Encoding Process:
        Click on the "Encode Video" button to start the encoding process.

    Monitor Progress:
        A progress bar and status label will provide real-time feedback on the encoding process.

### Decoding Data from a Video

    Select Decoding Mode:
        Click on the "Decode" tab in the GUI.

    Choose Video File:
        Click on the "Choose Video" button to select the video file from which you want to extract hidden data.

    Provide Encryption Key and Initialization Vector (IV):
        Enter the same encryption key and initialization vector used during encoding.

    Initiate Decoding Process:
        Click on the "Decode Video" button to start the decoding process.

    Monitor Progress:
        A progress bar and status label will provide real-time feedback on the decoding process.
 
### Key Generation

    Select Key Generation Mode:
        Click on the "Key Generation" tab in the GUI.

    Generate Keys:
        Click on the "Generate Keys" button to create a secure encryption key and initialization vector.

    Copy to Clipboard:
        Optionally, you can cop

