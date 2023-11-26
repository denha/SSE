import React from 'react'
import { Outlet } from 'react-router-dom'

import TopMenuBar from '../Components/TopMenuBar'
import Container from '../Components/Container'


const MainLayout = ()=>{
return <>
<TopMenuBar/>
<Container>
    <Outlet/>
</Container>

</> 


}

export default MainLayout