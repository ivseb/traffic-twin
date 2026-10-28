import { mount } from 'svelte';
import App from './App.svelte';
import { applyTheme } from './lib/stores.svelte';
import './app.css';

const target = document.getElementById('app');
if (!target) {
  throw new Error('missing #app mount point');
}

applyTheme();

export default mount(App, { target });
