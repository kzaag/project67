#include <alsa/asoundlib.h>
#include <alloca.h>

int main() {
  int key=0;
  long loops;
  int rc;
  int size;
  snd_pcm_t *handle, * output;
  snd_pcm_hw_params_t *params;
  unsigned int val;
  int dir;
  snd_pcm_uframes_t frames;
  char *buffer;
  int channels = 2;

  /* Open PCM device for recording (capture). */
//   rc = snd_pcm_open(&handle, "default", SND_PCM_STREAM_CAPTURE, 0);
//   if (rc < 0) {
//     fprintf(stderr, "unable to open pcm device: %s\n", snd_strerror(rc));
//     exit(1);
//   }

  /* Open PCM device for recording (capture). */
  rc = snd_pcm_open(&output, "default", SND_PCM_STREAM_PLAYBACK, 0);
  if (rc < 0) {
    fprintf(stderr, "unable to open pcm device: %s\n", snd_strerror(rc));
    exit(1);
  }

  /* Allocate a hardware parameters object. */
    snd_pcm_hw_params_alloca(&params);

  /* Fill it in with default values. */
//   snd_pcm_hw_params_any(handle, params);

//   /* Set the desired hardware parameters. */

//   /* Interleaved mode */
//   snd_pcm_hw_params_set_access(handle, params, SND_PCM_ACCESS_RW_INTERLEAVED);

//   /* Signed 16-bit little-endian format */
//   snd_pcm_hw_params_set_format(handle, params, SND_PCM_FORMAT_S16_LE);

//   /* One channel (mono) */
//   snd_pcm_hw_params_set_channels(handle, params, channels);

//   val = 44100;
//   snd_pcm_hw_params_set_rate_near(handle, params, &val, &dir);

//   /* Set period size to 512 frames. */
//   frames = 512;
//   snd_pcm_hw_params_set_period_size_near(handle, params, &frames, &dir);

//   /* Write the parameters to the driver */
//   rc = snd_pcm_hw_params(handle, params);
//   if (rc < 0) {
//     fprintf(stderr, "unable to set hw parameters: %s\n", snd_strerror(rc));
//     exit(1);
//   }


  /* Fill it in with default values. */
  snd_pcm_hw_params_any(output, params);

  /* Set the desired hardware parameters. */

  /* Interleaved mode */
  snd_pcm_hw_params_set_access(output, params, SND_PCM_ACCESS_RW_INTERLEAVED);

  /* Signed 16-bit little-endian format */
  snd_pcm_hw_params_set_format(output, params, SND_PCM_FORMAT_S16_LE);

  /* One channel (mono) */
  snd_pcm_hw_params_set_channels(output, params, channels);

  val = 44100;
  snd_pcm_hw_params_set_rate_near(output, params, &val, &dir);

  /* Set period size to 512 frames. */
  //frames = 512;
  //snd_pcm_hw_params_set_period_size_near(output, params, &frames, &dir);

  /* Write the parameters to the driver */
  rc = snd_pcm_hw_params(output, params);
  if (rc < 0) {
    fprintf(stderr, "unable to set hw parameters: %s\n", snd_strerror(rc));
    exit(1);
  }

snd_pcm_hw_params_get_period_size(params, &frames, 0);

  /* Use a buffer large enough to hold one period */
  snd_pcm_hw_params_get_period_size(params, &frames, &dir);
  size = frames * 2 * channels; /* 2 bytes/sample, 1 channels */
  buffer = (char *) malloc(size);

    FILE * fp = fopen("../1.wav", "r");
    if(fp == NULL)
        return 2;
    fseek(fp,44, SEEK_SET);
  while (1) 
  {

      if((rc = fread(buffer, 1, size, fp)) <= 0) {
          printf("%s\n", strerror(errno));
          return 2;
      }

    // rc = snd_pcm_readi(handle, buffer, frames);
    // if (rc == -EPIPE) 
    // {
    //   /* EPIPE means overrun */
    //   fprintf(stderr, "overrun occurred\n");
    //   snd_pcm_prepare(handle);
    // } 
    // else if (rc < 0)
    // {
    //   fprintf(stderr, "error from read: %s\n", snd_strerror(rc));
    // } 
    // else if (rc != (int)frames) 
    // {
    //   fprintf(stderr, "short read, read %d frames\n", rc);
    // }

		if (rc = snd_pcm_writei(output, buffer, frames) == -EPIPE) {
			printf("XRUN.\n");
			snd_pcm_prepare(output);
		} else if (rc < 0) {
			printf("ERROR. Can't write to PCM device. %s\n", snd_strerror(rc));
		}
    }

  snd_pcm_drain(handle);
  snd_pcm_close(handle);
  free(buffer);

  return 0;
}
