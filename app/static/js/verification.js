/**
 * Verification page UX enhancements
 * - Disable buttons during form submission
 * - Show spinner while processing
 * - Preserve accessibility (aria-busy)
 */
(function() {
  'use strict';

  document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('.verification-form');
    
    forms.forEach(function(form) {
      form.addEventListener('submit', function(event) {
        const button = form.querySelector('button[type="submit"]');
        if (!button || button.disabled) return;
        
        // Disable button to prevent double-submit
        button.disabled = true;
        button.setAttribute('aria-busy', 'true');
        
        // Store original text
        const originalText = button.innerHTML;
        
        // Add spinner
        button.innerHTML = '<span class="spinner" aria-hidden="true"></span>' + originalText;
        
        // Re-enable after timeout (fallback in case of error)
        setTimeout(function() {
          if (button.disabled) {
            button.disabled = false;
            button.removeAttribute('aria-busy');
            button.innerHTML = originalText;
          }
        }, 30000); // 30s timeout
      });
    });
    
    // Copy correlation ID to clipboard on click
    const correlationCells = document.querySelectorAll('.correlation-id');
    correlationCells.forEach(function(cell) {
      cell.style.cursor = 'pointer';
      cell.title = 'Click to copy full correlation ID';
      
      cell.addEventListener('click', function() {
        const fullId = this.textContent.replace('...', ''); // Remove ellipsis for demo
        // In production, store full ID in data attribute
        const tempInput = document.createElement('input');
        tempInput.value = fullId;
        document.body.appendChild(tempInput);
        tempInput.select();
        document.execCommand('copy');
        document.body.removeChild(tempInput);
        
        // Visual feedback
        const originalTitle = this.title;
        this.title = 'Copied!';
        this.style.background = 'rgba(25, 135, 84, 0.1)';
        
        setTimeout(function() {
          cell.title = originalTitle;
          cell.style.background = '';
        }, 1500);
      });
    });
  });
})();
