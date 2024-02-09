import './App.css';
import React, { useState, useEffect } from "react";
import Button from 'react-bootstrap/Button';
import NavbarComponent from './NavbarComponent';
import { Form, FormGroup, FormLabel, FormControl } from 'react-bootstrap';
import Row from 'react-bootstrap/Row';
import Col from 'react-bootstrap/Col';

function Trainer() {
  const [Msg, setMsg] = useState('');
  const [Msg2, setMsg2] = useState('');
  const [Layer, setLayer] = useState([{activation:"",nodes:""}]);
  
  useEffect(() => {
	
	async function fetchTrainingStatus() {

		const response = await fetch('https://danielmackey.ie/api/TrainingInfo/', {method:'GET',});
		
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
	try {
		const hyperparameters = {
		Layers:Layer
		}
		
		setMsg('Training started.');
		const STresponse = await fetch(`https://danielmackey.ie/api/StartTraining/`, 
		{method:'POST',
		body: JSON.stringify(hyperparameters),
		headers: {
		  'X-CSRFToken': csrftoken,
		  'Content-Type': 'application/json',
		}
		});

		   const currDateTime = new Date().toLocaleDateString() + " " + new Date().toLocaleTimeString();
                   
		   const data = {
                   status: "Last previous training session:",
                   previousTimestamp: currDateTime,
                   };
                   
		   const response = await fetch(`https://danielmackey.ie/api/TrainingInfo/`, 
		   { method:'POST',
		   body: JSON.stringify(data),
		   
		   headers: {
                  'Content-Type': 'application/json',
                  'X-CSRFToken': csrftoken,
                 },
		   
		   
		});
		
		setMsg(data.status);
		setMsg2(data.previousTimestamp);
		
		} catch (error) {
		  	setMsg('error')
		}
  }
  const handleClick = () => {
  	setLayer([...Layer,{activation:"",nodes:""}])
  }
  const handleChange = (entered,index) => {
  	const {name,value}=entered.target
  	const onChangeLayer = [...Layer]
  	onChangeLayer[index][name]=value
  	setLayer(onChangeLayer)
  }
  const handleDelete = (index) => {
  	const deleteData = [...Layer]
  	deleteData.splice(index,1)
  	setLayer(deleteData)
  }

  return (
	<>
	<container>
	<div class="row justify-content-md-center">
	<form className="form-inline">
	<NavbarComponent/>
		<h5 class="mt-3">{Msg}</h5>
			{Msg2}
		<div class="mb-4">
			<button onClick={StartTraining} type="button" className="btn btn-success">Start Training</button>
		</div>
		
  <Button onClick={handleClick} variant="primary" className="mb-2">Add Layer</Button>
  {Layer.map((layer, index) => (
    <div className="row mb-4" key={index}>
      <div className="col-md-2">
        <label>Activation Layer</label>
        <input 
          type="text" 
          className="form-control" 
          name="activation" 
          value={layer.activation} 
          onChange={(entered) => handleChange(entered, index)} 
          placeholder="Activation Layer"
        />
      </div>
      <div className="col-md-2">
        <label>Nodes</label>
        <input 
          type="text" 
          className="form-control" 
          name="nodes" 
          value={layer.nodes} 
          onChange={(entered) => handleChange(entered, index)} 
          placeholder="Nodes" 
        />
      </div>
      <div className="col-md-2">
        <button 
          onClick={() => handleDelete(index)} 
          className="btn btn-danger" 
          type="button">
          Remove
        </button>
      </div>
    </div>

  ))}
</form>
</div>
</container>
        </>            
    );	
}

export default Trainer;
