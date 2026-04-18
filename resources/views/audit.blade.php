<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Heimdall — Security Audit</title>
    <script>
        if (localStorage.getItem('theme') !== 'light') {
            document.documentElement.classList.add('dark');
        }
    </script>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
    @livewireStyles
</head>
<body class="bg-gray-100 dark:bg-gray-950 overflow-hidden">
    <livewire:vault.audit />
    <x-confirm-modal />
    @livewireScripts
</body>
</html>
