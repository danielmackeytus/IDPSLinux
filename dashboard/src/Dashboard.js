import './App.css';
import styles from './Dashboard.module.css';
import React, { useState, useEffect } from "react";
import NavbarComponent from './NavbarComponent';
import { PieChart } from '@mui/x-charts/PieChart';
import Container from 'react-bootstrap/Container';

function Dashboard() {
   const [FlowStatistics, setFlowStatistics] = useState({});
   const [PieChartFA, setPieChartFA] = useState([{id:0,value:0,label:""}]);
   const [PieChartFO, setPieChartFO] = useState([{id:1,value:0,label:""}]);

   useEffect(() => {

	async function FetchFlowStatistics() {
            const response = await fetch('https://danielmackey.ie/api/FetchFlowStatistics/', {
            credentials: 'include',
            });

            const flowStatistics = await response.json();

            if (flowStatistics.FrequentAttack) {
              const updatedData = flowStatistics.FrequentAttack
              .filter(item => item.Label !== '0')
                .map((item, index) => ({
                    id: index,
                    value: item.count,
                    label: item.Label,
              }));


        setPieChartFA(updatedData);
      }

            if (flowStatistics.FrequentOrigin) {
              const updatedData = flowStatistics.FrequentOrigin
              .filter(item => item.Origin !== 'Nowhere')
                .map((item, index) => ({
                    id: index,
                    value: item.count,
                    label: item.Origin,
              }));


        setPieChartFO(updatedData);
      }
            setFlowStatistics(flowStatistics)
	    }
	
	FetchFlowStatistics();
  }, []);


return (
<>
  <NavbarComponent/>
  <Container fluid>

  <h3 className="mt-5"><p>Top 5 most frequent attacks</p></h3>

    <PieChart
      series={[

        {data: PieChartFA,
        },
      ]
      }

      width={550}
      height={200}
      margin={{left:-50}}

    />

 {FlowStatistics.FrequentAttack && FlowStatistics.FrequentAttack.map((item,index) => (
 item.Label != '0' ? (

  <ul>
     <li key={index}>Type: {item.Label} - Count: {item.count}</li>

  </ul>

  ): null))
  }

  <h3 className="mt-5"><p>Top 5 most frequent origins</p></h3>

    <PieChart
      series={[

        {data: PieChartFO},
      ]}
      width={550}
      height={200}
      margin={{left:-50}}

    />

 {FlowStatistics.FrequentOrigin && FlowStatistics.FrequentOrigin.map((item,index) => (
 item.Origin != 'Nowhere' ? (
 <ul>
     <li key={index}>Type: {item.Origin} - Count: {item.count}</li>
  </ul>

  ): null))
  }
</Container>
</>
  
);
}
export default Dashboard;
