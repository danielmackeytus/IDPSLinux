import './App.css';
import React, { useState, useEffect } from "react";
import Button from 'react-bootstrap/Button';
import NavbarComponent from './NavbarComponent';
import { Form, FormGroup, FormLabel, FormControl } from 'react-bootstrap';
import Row from 'react-bootstrap/Row';
import Col from 'react-bootstrap/Col';
import Container from 'react-bootstrap/Container';

function Trainer() {
  const [Msg, setMsg] = useState('');
  const [Msg2, setMsg2] = useState('');
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
                   
                   setMsg(data[0].status);
                   setMsg2(data[0].previousTimestamp);
		   
		   
		} else {
		   setMsg('No connection to backend.')
		}
	}
	fetchTrainingStatus();
  }, []);
  
  
  function getCSRFToken() {
  
     const cookieString = document.cookie;
     const csrfCookie = cookieString
       .split(';')
       .find((cookie) => cookie.trim().startsWith('csrftoken='));

     if (!csrfCookie) {
       throw new Error('CSRF token not found in cookies.');
  }

  return csrfCookie.split('=')[1];
}

  const csrftoken = getCSRFToken();
  
  const StartTraining = async ()  => {
	setMsg('Starting training..');

	const hyperparameters = {
	   Layers:Layer,
	   Epochs:epochs
	}
		
		
	const STresponse = await fetch(`https://localhost:8000/api/StartTraining/`,
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
           setMsg('Training started.');
	   const currDateTime = new Date().toLocaleDateString() + " " + new Date().toLocaleTimeString();
                   
	const data = {
           status: "Last previous training session:",
           previousTimestamp: currDateTime,
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
		
	setMsg(data[0].status);
	setMsg2(data[0].previousTimestamp);
	} else {
	   setMsg('No training files found.')
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

  return (
  <>
    <NavbarComponent/>

<Container fluid>
    <Form className="form">

		<h5 class="mt-4">{Msg}</h5>
			{Msg2}
		<div class="mt-2 mb-4">
			<button onClick={StartTraining} type="button" className="btn btn-success">Start Training</button>
		</div>

  <Col className="col-md-2">
        <label>Epochs</label>
        <input 
          type="text" 
          className="form-control" 
          name="epochs" 
          value={epochs} 
          onChange={(entered) => handleChange(entered)} 
          placeholder="Enter Epochs"
        />
      </Col>
  <Button onClick={handleClick} variant="primary" className="mt-4 mb-2">Add Layer</Button>
  {Layer.map((layer, index) => (
    <Row className="row" key={index}>
      <Col className="col-md-2">
        <label>Activation Layer</label>
        <input 
          type="text" 
          className="form-control" 
          name="activation" 
          value={layer.activation} 
          onChange={(entered) => handleLayerChange(entered, index)} 
          placeholder="Activation Layer"
        />
      </Col>
      <Col className="col-md-2">
        <label>Nodes</label>
        <input 
          type="text" 
          className="form-control" 
          name="nodes" 
          value={layer.nodes} 
          onChange={(entered) => handleLayerChange(entered, index)} 
          placeholder="Nodes" 
        />
      </Col>

      <Col className="col-md-2">
        <button onClick={() => handleDelete(index)}
          className="mt-4 btn btn-danger"
          type="button">
          Remove
        </button>
      </Col>
    </Row>

  ))}



</Form></Container>
</>
    );	
}

export default Trainer;
