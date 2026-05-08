<?php

use App\Http\Controllers\Api\ExtensionController;
use App\Http\Middleware\ExtensionTokenAuth;
use Illuminate\Support\Facades\Route;

Route::prefix('extension')->group(function () {
    Route::post('/login', [ExtensionController::class, 'login']);

    Route::middleware(ExtensionTokenAuth::class)->group(function () {
        Route::get('/entries', [ExtensionController::class, 'entries']);
        Route::post('/logout', [ExtensionController::class, 'logout']);
    });
});
