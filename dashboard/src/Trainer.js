import './App.css';
import React, { useState, useEffect } from "react";
import Button from 'react-bootstrap/Button';
import NavbarComponent from './NavbarComponent';
import { Form, FormGroup, FormLabel, FormControl } from 'react-bootstrap';
import Row from 'react-bootstrap/Row';
import Card from 'react-bootstrap/Card';
import Col from 'react-bootstrap/Col';
import Container from 'react-bootstrap/Container';

function Trainer() {
  const [Status, setStatus] = useState('Awaiting status update');
  const [Timestamp, setTimestamp] = useState('Finding Timestamp..');
  const [validation_accuracy, setValidationAccuracy] = useState('null');
  const [validation_loss, setValidationLoss] = useState('null');
  const [accuracy, setAccuracy] = useState('null');
  const [accuracy_loss, setAccuracy_loss] = useState('null');
  const [Layer, setLayer] = useState([{activation:"",nodes:""}]);
  const [epochs, setEpochs] = useState()
  
  useEffect(() => {

	async function fetchTrainingStatus() {

		const response = await fetch('https://danielmackey.ie/api/TrainingInfo/', {
		   method:'GET',
		   credentials: 'include',
                });
		
                if (response.ok) {
                   const data = await response.json();

                   setTimestamp(data.previousTimestamp);
		   
		   
		} else {
		   setStatus('No connection to backend.')
		}
	}
	async function fetchTFPerformanceMetrics() {

		const response = await fetch('https://danielmackey.ie/api/MetricInfo/', {
		   method:'GET',
		   credentials: 'include',
                });

                if (response.ok) {
                   const data = await response.json();

                   setAccuracy(data.accuracy);
                   setAccuracy_loss(data.loss);
                   setValidationAccuracy(data.val_accuracy);
                   setValidationLoss(data.val_loss);

		} else {
		   setStatus('No connection to backend.')
		}
	}

	fetchTrainingStatus();
	fetchTFPerformanceMetrics();
  }, []);
  
  
  function getCSRFToken() {
  
     const cookieString = document.cookie;
     const csrfCookie = cookieString
       .split(';')
       .find((cookie) => cookie.trim().startsWith('csrftoken='));

     if (!csrfCookie) {
       return 0
  }

  return csrfCookie.split('=')[1];
}

  const csrftoken = getCSRFToken();
  
  const StartTraining = async ()  => {
	setStatus('Starting training..');

	const hyperparameters = {
	   Layers:Layer,
	   Epochs:epochs,
	}


	const STresponse = await fetch(`https://danielmackey.ie/api/StartTraining/`,
	   {method:'POST',
	   credentials: 'include',
	   body: JSON.stringify(hyperparameters),
	   headers: {
	   'X-CSRFToken': csrftoken,
	   'Content-Type': 'application/json',
		}
	});

	const data = await STresponse.json();

        if (data.status != 'No training files found.') {
           setStatus('Training started.');
	   const currDateTime = new Date().toLocaleDateString() + " " + new Date().toLocaleTimeString();

	const data = {
           previousTimestamp: currDateTime,
           status: Status,
        };
                   
	const response = await fetch(`https://danielmackey.ie/api/TrainingInfo/`,
	   { method:'POST',
	   credentials: 'include',
	   body: JSON.stringify(data),
		   
	   headers: {
           'Content-Type': 'application/json',
           'X-CSRFToken': csrftoken,
                 },
	});

	setTimestamp(data.previousTimestamp);
	//setStatus(data.Status);
	} else {
	   setStatus('No training files found.')
	   }
		
	}
  
  const handleClick = () => {
  	setLayer([...Layer,{activation:"",nodes:""}])
  }
  const handleLayerChange = (entered,index) => {
  	const {name,value}=entered.target
  	const onChangeLayer = [...Layer]
  	onChangeLayer[index][name]=value
  	setLayer(onChangeLayer)
  }
  
  const handleChange = (entered) => {
  	setEpochs(entered.target.value)
  }
  const handleDelete = (index) => {
  	const deleteData = [...Layer]
  	deleteData.splice(index,1)
  	setLayer(deleteData)
  }

  const AbuseIPDB = async ()  => {
	try {
	    setStatus('AbuseIPDBing..');
		const response = await fetch(`https://danielmackey.ie/api/AbuseIPDB/`, {
		method: 'GET',
		credentials: 'include',
  	    });

		if (!response.ok){
			setStatus("No connection to backend.")
		}
    } catch(error) {
        console.log('an error occurred.')
    }
    }

  return (
  <>
    <NavbarComponent/>

<Container fluid>
  <Row>

    <Col md="6" className="mb-4"><Card>
  <Card.Body>
      <h4 class="mb-4">{Status}</h4>
      <h6>Previous Training Session</h6>
      <p>{Timestamp}</p>
      <Button onClick={StartTraining} variant="success" className="mt-2">Start Training</Button>
    </Card.Body>
    </Card></Col>

    <Col md="6" className="text-center">
      <h3>Model Performance Metrics</h3>
      <p><strong>Accuracy:</strong> {accuracy}</p>
      <p><strong>Accuracy Loss:</strong> {accuracy_loss}</p>
      <p><strong>Validation Accuracy:</strong> {validation_accuracy}</p>
      <p><strong>Validation Loss:</strong> {validation_loss}</p>
    </Col>


    </Row>
    <Row>
    <Col md="4">
      <Form.Label>Epochs</Form.Label>
      <Form.Control
        type="text"
        value={epochs}
        onChange={handleChange}
        placeholder="Enter Epochs"
      />
      <Button onClick={handleClick} variant="primary" className="mt-4">Add Layer</Button>
      </Col>

      {Layer.map((layer, index) => (
        <Row key={index} className="align-items-end">
        <Col md="3" className="mt-4">
        <Form.Label>Activation Function</Form.Label>
        <Form.Control
            type="text"
            name="activation"
            value={layer.activation}
            onChange={(entered) => handleLayerChange(entered, index)}
            placeholder="Activation Function"
      />
    </Col>

    <Col md="2" className="mt-4">
      <Form.Label>Nodes</Form.Label>
      <Form.Control
        type="text"
        name="nodes"
        value={layer.nodes}
        onChange={(entered) => handleLayerChange(entered, index)}
        placeholder="Nodes"
      />
    </Col>
    <Col md="2" className="mt-4">

      <Button onClick={() => handleDelete(index)} variant="danger" className="mt-4">
        Remove
      </Button>
    </Col>
  </Row>
))}
  </Row>
</Container>
</>
    );	
}

export default Trainer;
