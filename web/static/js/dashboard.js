// PHAROS Drag-and-Drop Uploader and Async Status Poller
document.addEventListener('DOMContentLoaded', () => {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const uploadPanel = document.getElementById('upload-panel');
  const processingPanel = document.getElementById('processing-panel');
  const stageTicker = document.getElementById('processing-stage-text');
  const currentFilename = document.getElementById('processing-filename-text');

  if (!dropzone || !fileInput) return;

  // Click to browse
  dropzone.addEventListener('click', () => fileInput.click());

  // Drag and drop event handlers
  ['dragenter', 'dragover'].forEach(name => {
    dropzone.addEventListener(name, (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(name => {
    dropzone.addEventListener(name, (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files && fileInput.files.length > 0) {
      handleFileUpload(fileInput.files[0]);
    }
  });

  function handleFileUpload(file) {
    const validExtensions = ['.docx', '.docm', '.doc'];
    const name = file.name.toLowerCase();
    const isSupported = validExtensions.some(ext => name.endsWith(ext));

    if (!isSupported) {
      alert('Phase 1 supports Word documents only (.docx, .docm, .doc).');
      return;
    }

    // Switch view to Processing Panel with Mesmerizing Animation
    uploadPanel.style.display = 'none';
    processingPanel.classList.add('active');
    currentFilename.textContent = file.name;
    stageTicker.textContent = 'Uploading and staging container...';

    const formData = new FormData();
    formData.append('file', file);

    fetch('/api/scan', {
      method: 'POST',
      body: formData,
    })
      .then(res => {
        if (!res.ok) throw new Error('Upload submission failed.');
        return res.json();
      })
      .then(data => {
        if (data.scan_id) {
          pollScanProgress(data.scan_id);
        } else {
          throw new Error(data.error || 'No scan ID returned.');
        }
      })
      .catch(err => {
        alert('Scan Error: ' + err.message);
        uploadPanel.style.display = 'block';
        processingPanel.classList.remove('active');
      });
  }

  function pollScanProgress(scanId) {
    const pollInterval = setInterval(() => {
      fetch(`/api/scan/${scanId}/status`)
        .then(res => res.json())
        .then(statusData => {
          if (statusData.stage) {
            stageTicker.textContent = statusData.stage;
          }

          if (statusData.status === 'completed') {
            clearInterval(pollInterval);
            stageTicker.textContent = 'Redirecting to Security Intelligence Report...';
            setTimeout(() => {
              window.location.href = `/report/${scanId}`;
            }, 600);
          } else if (statusData.status === 'failed') {
            clearInterval(pollInterval);
            alert('Scan Failed: ' + (statusData.error || 'Unknown processing error.'));
            uploadPanel.style.display = 'block';
            processingPanel.classList.remove('active');
          }
        })
        .catch(err => {
          console.error('Polling error:', err);
        });
    }, 700);
  }
});
