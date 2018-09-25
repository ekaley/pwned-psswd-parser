package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/alexflint/go-arg"

	log "github.com/sirupsen/logrus"
)

var args struct {
	PwnedPasswdFilePath string `help:"Dataset to check. Full file path for pwned-passwords-xx.txt"`
	ChkPasswdFilePath   string `help:"full file path for user-passwords.txt"`
}

// type chunk struct {
// 	bufsize   int
// 	offset    int
// 	dataChunk []string
// }

func init() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	// Only log the warning severity or above.
	log.SetLevel(log.DebugLevel)
}

func main() {
	// take in file path
	args.PwnedPasswdFilePath = "/home/tom/Documents/pwned-passwords-ordered-by-count.txt"
	args.ChkPasswdFilePath = "./user-passwords.txt"
	arg.MustParse(&args)
	// log password inputs to hash and cross reference
	log.WithFields(log.Fields{
		"dataset":  args.PwnedPasswdFilePath,
		"checkset": args.ChkPasswdFilePath,
	}).Info("Input dataset will be crossreferenced against input checkset")

	// call read() to get user passwd dataset
	// make channel to throw read chunks onto
	// chkPasswdDatasetChan := make(chan chunk, 10)
	// defer close(chkPasswdDatasetChan)
	// err := read(args.ChkPasswdFilePath, chkPasswdDatasetChan)
	// if err != nil {
	// 	log.WithFields(log.Fields{
	// 		"dataset": args.ChkPasswdFilePath,
	// 		"error":   err,
	// 	}).Fatal("Input dataset failed to be read")
	// }
	// call read() to get pwned passwd dataset
	// make channel to throw read chunks onto
	// pwnedPasswdDatasetChan := make(chan chunk, 1000)
	// defer close(pwnedPasswdDatasetChan)
	// err = read(args.PwnedPasswdFilePath, pwnedPasswdDatasetChan)
	// if err != nil {
	// 	log.WithFields(log.Fields{
	// 		"dataset": args.PwnedPasswdFilePath,
	// 		"error":   err,
	// 	}).Fatal("Input dataset failed to be read")
	// }

	// compare all the things
	compare()
}

// func read(path string, readChan chan (chunk)) (err error) {

// 	bufferSize := int(1000)
// 	dataset, err := os.Open(path)
// 	if err != nil {
// 		log.WithFields(log.Fields{
// 			"dataset": path,
// 		}).Fatal("Input dataset failed to be opened")
// 		return
// 	}
// 	defer dataset.Close()

// 	datasetInfo, err := dataset.Stat()
// 	if err != nil {
// 		log.WithFields(log.Fields{
// 			"dataset": path,
// 		}).Fatal("Input dataset failed to be Stat(ed)")
// 		return
// 	}

// 	// get size of dataset
// 	datasetSize := int(datasetInfo.Size())
// 	// calc our go routines
// 	routines := datasetSize / bufferSize
// 	// make chunks
// 	chunkSizes := make([]chunk, routines)

// 	for i := 0; i < routines; i++ {
// 		chunkSizes[i].bufsize = bufferSize
// 		chunkSizes[i].offset = bufferSize * i
// 		chunkSizes[i].dataChunk = make([]string, bufferSize)
// 	}

// 	// make sure we dont miss any trailing lines when dividing
// 	if r := datasetSize % bufferSize; r != 0 {
// 		// add another chunk
// 		c := chunk{
// 			bufsize: r,
// 			offset:  routines * bufferSize,
// 		}
// 		chunkSizes = append(chunkSizes, c)
// 		// add moar routine
// 		routines++
// 	}

// 	var wg sync.WaitGroup
// 	wg.Add(routines)

// 	log.Info("Starting to read in chunks")

// 	for i := 0; i < routines; i++ {
// 		go func(chunkSizes []chunk, i int) {
// 			defer wg.Done()

// 			chunk := chunkSizes[i]
// 			// readBuffer := make([]string, chunk.bufsize)
// 			// bytesRead, err := dataset.ReadAt(readBuffer, int64(chunk.offset))
// 			scanner := bufio.NewScanner(dataset)
// 			if path == args.ChkPasswdFilePath {
// 				for scanner.Scan() {
// 					line := scanner.Bytes()
// 					lineSHA1 := sha1.Sum(line)
// 					fmt.Println("here1")
// 					// gnarly 1 liner below
// 					chunk.dataChunk = append(chunk.dataChunk, string(lineSHA1[:]))
// 				}
// 			}
// 			if path == args.PwnedPasswdFilePath {
// 				for scanner.Scan() {
// 					line := scanner.Text()
// 					fmt.Println("here2")
// 					chunk.dataChunk = append(chunk.dataChunk, line)
// 				}
// 			}
// 			if scanner.Err() != nil {
// 				log.WithFields(log.Fields{
// 					"readOffset": chunk.offset,
// 				}).Warn("Failed to scann in chunks")
// 				return
// 			}
// 			fmt.Println("here3")
// 			readChan <- chunk

// 		}(chunkSizes, i)
// 	}
// 	// collect all the things
// 	wg.Wait()
// 	return
// }

func compare() {
	chkDataset, err := os.Open(args.ChkPasswdFilePath)
	if err != nil {
		log.WithFields(log.Fields{
			"dataset": chkDataset,
		}).Fatal("Input dataset failed to be opened")
		return
	}
	defer chkDataset.Close()

	pwnedDataset, err := os.Open(args.PwnedPasswdFilePath)
	if err != nil {
		log.WithFields(log.Fields{
			"dataset": pwnedDataset,
		}).Fatal("Input dataset failed to be opened")
		return
	}
	defer pwnedDataset.Close()

	chkDatasetInfo, err := chkDataset.Stat()

	if err != nil {
		log.WithFields(log.Fields{}).Fatal("Input dataset failed to be Stat(ed)")
		return
	}
	// TODO make size line count not byte size
	chkArray := make(map[string]int, chkDatasetInfo.Size())
	scanner := bufio.NewScanner(chkDataset)
	i := 1
	for scanner.Scan() {
		line := scanner.Bytes()
		lineSHA1 := sha1.Sum(line)
		s := fmt.Sprintf("%X", lineSHA1)
		// fmt.Println(s)
		chkArray[s] = i
		i++
	}

	// var wg sync.WaitGroup
	// for , sha := range  {
	// wg.Add(chkPasswdChunkIndex)
	// for i := 0; i <= len(chkPasswdChunk.dataChunk); i++ {
	// 	go func(sha string, pwnedPasswdDatasetChan chan (chunk)) {

	//

	pwnedFoundList := make(map[string]int)

	scanner = bufio.NewScanner(pwnedDataset)
	for scanner.Scan() {
		line := scanner.Text()
		l := strings.Split(line, ":")
		for k, v := range chkArray {
			if l[0] == k {
				log.WithFields(log.Fields{
					"chkArrayPasswdIndex": v,
					"pwnedPasswordSha1":   l[0],
				}).Info("You've been Pwned. Change that password.")
				pwnedFoundList[l[0]] = v
			}
		}
		if scanner.Err() != nil {
			log.WithFields(log.Fields{
				"err": scanner.Err(),
			}).Warn("Failed to scan in dataset")
			return
		}
	}

	// write out found sha1 and user passwd index location
	pwnedBytes, err := json.Marshal(pwnedFoundList)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Warn("Failed to marshall final results file.")
	}

	err = ioutil.WriteFile("pwnedFoundList.txt", pwnedBytes, 0644)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Warn("Failed to write out final results file.")
	}
}
