<script lang="ts">
  // Old address of "Scenari mock": the saved scenarios are a tab of the Mock page now.
  import { onMount } from 'svelte';
  import Loading from '../components/Loading.svelte';
  import { navigate } from '../lib/router.svelte';

  onMount(() => navigate('/mock', { tab: 'saved' }, true));
</script>

<Loading />
