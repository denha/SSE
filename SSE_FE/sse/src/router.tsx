import React from 'react';
import { createBrowserRouter } from 'react-router-dom';

import AuthLayout from './Layout/AuthLayout';
import Login from './Pages/Login';
import Register from './Pages/Register';
import MainLayout from './Layout/MainLayout';
import Home from './Pages/Home';
import KeyPair from './Pages/KeyPair';
import Search from './Pages/Search/Search';
import FileViewer from './Pages/FileViewer/FileViewer';

export const router = createBrowserRouter([

{

element:<AuthLayout/>,
children: [
    {path:"login",element:<Login/>},
    {path:'register',element:<Register/>}
]
},{
    element:<MainLayout/>,
    children:[
        {path:'home',element:<Home/>},
        {path:'key-pair',element:<KeyPair/>},
        {path:'search',element:<Search/>},
        {path:'file-viewer/:file',element:<FileViewer/>}
    ]
}

])