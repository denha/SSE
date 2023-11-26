import React, { useState, useEffect } from 'react';

type AlertProp ={
    message?:string,
    duration?:number,
    type?:string
}
const Alert = ({ message, duration, type }:AlertProp) => {
  const [showAlert, setShowAlert] = useState(true);

  useEffect(() => {
    const timeout = setTimeout(() => {
      setShowAlert(false);
    }, duration);

    return () => {
      clearTimeout(timeout);
    };
  }, [duration]);

  return (
    showAlert ? (
      <div className={`alert alert-${type}`} role="alert" style={{margin:'1rem 0rem'}}>
        {message}
      </div>
    ): <></>
  );
};

export default Alert;
